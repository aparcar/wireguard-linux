// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 WireGuard PQC Contributors. All Rights Reserved.
 */

#include "pqc.h"
#include "device.h"
#include "peer.h"
#include "noise.h"
#include "socket.h"
#include "cookie.h"
#include "timers.h"
#include "messages.h"

#include <linux/mutex.h>
#include <linux/slab.h>

DEFINE_STATIC_KEY_FALSE(wg_pqc_enabled);

u32 wg_pqc_init_payload_len;
u32 wg_pqc_resp_payload_len;
u32 wg_pqc_init_msg_len;
u32 wg_pqc_resp_msg_len;

struct wg_pqc_ops __rcu *wg_pqc_current;
static DEFINE_MUTEX(wg_pqc_lock);

int wg_pqc_register(struct wg_pqc_ops *ops)
{
	int ret = 0;

	if (!ops->get_pq_payload_len || !ops->append_pq || !ops->consume_pq)
		return -EINVAL;

	mutex_lock(&wg_pqc_lock);
	if (rcu_dereference_protected(wg_pqc_current,
				      lockdep_is_held(&wg_pqc_lock))) {
		ret = -EBUSY;
		goto out;
	}

	/* Cache payload sizes from the extension */
	wg_pqc_init_payload_len = ops->get_pq_payload_len(true);
	wg_pqc_resp_payload_len = ops->get_pq_payload_len(false);

	/* Validate payload sizes */
	if (wg_pqc_init_payload_len > WG_PQC_MAX_PAYLOAD ||
	    wg_pqc_resp_payload_len > WG_PQC_MAX_PAYLOAD) {
		ret = -EMSGSIZE;
		goto out;
	}

	/* Compute total message sizes: classical + pq payload + MACs */
	wg_pqc_init_msg_len = WG_CLASSICAL_INITIATION_LEN +
			      wg_pqc_init_payload_len +
			      sizeof(struct message_macs);
	wg_pqc_resp_msg_len = WG_CLASSICAL_RESPONSE_LEN +
			      wg_pqc_resp_payload_len +
			      sizeof(struct message_macs);

	rcu_assign_pointer(wg_pqc_current, ops);
	static_branch_enable(&wg_pqc_enabled);

out:
	mutex_unlock(&wg_pqc_lock);
	return ret;
}
EXPORT_SYMBOL(wg_pqc_register);

void wg_pqc_unregister(struct wg_pqc_ops *ops)
{
	mutex_lock(&wg_pqc_lock);
	if (rcu_dereference_protected(wg_pqc_current,
				      lockdep_is_held(&wg_pqc_lock)) == ops) {
		RCU_INIT_POINTER(wg_pqc_current, NULL);
		static_branch_disable(&wg_pqc_enabled);
	}
	mutex_unlock(&wg_pqc_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL(wg_pqc_unregister);

void wg_pqc_send_handshake_initiation(struct wg_peer *peer)
{
	struct wg_pqc_ops *ops;
	u8 *packet;

	net_dbg_ratelimited("%s: Sending PQC handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	packet = kzalloc(wg_pqc_init_msg_len, GFP_KERNEL);
	if (unlikely(!packet))
		return;

	/* Phase 1: Classical Noise IK — writes the first 116 bytes.
	 * This calls the existing unmodified function which sets
	 * header.type = MESSAGE_HANDSHAKE_INITIATION and populates
	 * e, enc_s, enc_ts fields. It also updates handshake->chaining_key
	 * and handshake->hash with the classical DH results.
	 */
	if (!wg_noise_handshake_create_initiation(
			(struct message_handshake_initiation *)packet,
			&peer->handshake))
		goto out;

	/* Set the PQC flag bit in the header */
	((struct message_header *)packet)->type |= WG_PQC_FLAG;

	/* Phase 2: PQ extension — append after classical fields */
	rcu_read_lock();
	ops = rcu_dereference(wg_pqc_current);
	if (unlikely(!ops)) {
		rcu_read_unlock();
		goto out;
	}

	if (ops->append_pq(&peer->handshake,
			   packet + WG_CLASSICAL_INITIATION_LEN,
			   wg_pqc_init_payload_len,
			   peer, true)) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	/* MACs over the full message (classical + PQ), placed at the end */
	wg_cookie_add_mac_to_packet(packet, wg_pqc_init_msg_len, peer);

	wg_timers_any_authenticated_packet_traversal(peer);
	wg_timers_any_authenticated_packet_sent(peer);
	atomic64_set(&peer->last_sent_handshake,
		     ktime_get_coarse_boottime_ns());
	wg_socket_send_buffer_to_peer(peer, packet, wg_pqc_init_msg_len,
				      HANDSHAKE_DSCP);
	wg_timers_handshake_initiated(peer);

out:
	kfree_sensitive(packet);
}

void wg_pqc_send_handshake_response(struct wg_peer *peer)
{
	struct wg_pqc_ops *ops;
	u8 *packet;

	net_dbg_ratelimited("%s: Sending PQC handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	packet = kzalloc(wg_pqc_resp_msg_len, GFP_KERNEL);
	if (unlikely(!packet))
		return;

	/* Phase 1: Classical Noise IK response */
	if (!wg_noise_handshake_create_response(
			(struct message_handshake_response *)packet,
			&peer->handshake))
		goto out;

	/* Set the PQC flag bit */
	((struct message_header *)packet)->type |= WG_PQC_FLAG;

	/* Phase 2: PQ extension */
	rcu_read_lock();
	ops = rcu_dereference(wg_pqc_current);
	if (unlikely(!ops)) {
		rcu_read_unlock();
		goto out;
	}

	if (ops->append_pq(&peer->handshake,
			   packet + WG_CLASSICAL_RESPONSE_LEN,
			   wg_pqc_resp_payload_len,
			   peer, false)) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	/* MACs over the full message */
	wg_cookie_add_mac_to_packet(packet, wg_pqc_resp_msg_len, peer);

	if (wg_noise_handshake_begin_session(&peer->handshake,
					     &peer->keypairs)) {
		wg_timers_session_derived(peer);
		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		wg_socket_send_buffer_to_peer(peer, packet,
					      wg_pqc_resp_msg_len,
					      HANDSHAKE_DSCP);
	}

out:
	kfree_sensitive(packet);
}

struct wg_peer *wg_pqc_consume_initiation(struct wg_device *wg,
					   struct sk_buff *skb)
{
	struct message_handshake_initiation *msg;
	struct wg_pqc_ops *ops;
	struct wg_peer *peer;

	msg = (struct message_handshake_initiation *)skb->data;

	/* Temporarily clear PQC flag so classical consume works.
	 * The classical code checks header.type == MESSAGE_HANDSHAKE_INITIATION.
	 */
	msg->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);

	peer = wg_noise_handshake_consume_initiation(msg, wg);
	if (unlikely(!peer)) {
		pr_debug("wireguard: PQC consume_init: classical consume failed\n");
		return NULL;
	}

	/* Downgrade check: if peer requires PQC, we should be here (good).
	 * But also verify the extension is still loaded.
	 */
	rcu_read_lock();
	ops = rcu_dereference(wg_pqc_current);
	if (unlikely(!ops)) {
		rcu_read_unlock();
		wg_peer_put(peer);
		return NULL;
	}

	{
		int err = ops->consume_pq(&peer->handshake,
					  skb->data + WG_CLASSICAL_INITIATION_LEN,
					  wg_pqc_init_payload_len,
					  peer, true);
		if (err) {
			pr_debug("wireguard: PQC consume_init: consume_pq failed: %d\n", err);
			rcu_read_unlock();
			wg_peer_put(peer);
			return NULL;
		}
	}
	rcu_read_unlock();

	return peer;
}

struct wg_peer *wg_pqc_consume_response(struct wg_device *wg,
					  struct sk_buff *skb)
{
	struct message_handshake_response *msg;
	struct wg_pqc_ops *ops;
	struct wg_peer *peer;

	msg = (struct message_handshake_response *)skb->data;

	/* Temporarily clear PQC flag */
	msg->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);

	peer = wg_noise_handshake_consume_response(msg, wg);
	if (unlikely(!peer))
		return NULL;

	rcu_read_lock();
	ops = rcu_dereference(wg_pqc_current);
	if (unlikely(!ops)) {
		rcu_read_unlock();
		wg_peer_put(peer);
		return NULL;
	}

	if (ops->consume_pq(&peer->handshake,
			    skb->data + WG_CLASSICAL_RESPONSE_LEN,
			    wg_pqc_resp_payload_len,
			    peer, false)) {
		rcu_read_unlock();
		wg_peer_put(peer);
		return NULL;
	}
	rcu_read_unlock();

	return peer;
}
