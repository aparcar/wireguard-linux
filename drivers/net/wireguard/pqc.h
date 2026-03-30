/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 WireGuard PQC Contributors. All Rights Reserved.
 */

#ifndef _WG_PQC_H
#define _WG_PQC_H

#include "messages.h"
#include "noise.h"

#include <linux/types.h>
#include <linux/jump_label.h>

struct wg_peer;
struct wg_device;

/**
 * struct wg_pqc_ops - PQC extension callbacks
 *
 * A single PQC extension can be registered at a time. The extension provides
 * handshake callbacks and Netlink callbacks. WireGuard is entirely
 * algorithm-agnostic — it does not know which PQC algorithms the
 * extension uses.
 *
 * For kernel module extensions, the callbacks have direct access to
 * handshake->chaining_key and handshake->hash. For eBPF extensions,
 * access is through kfuncs (bpf_wg_mix_hash, bpf_wg_mix_key, etc.).
 */
struct wg_pqc_ops {
	/*
	 * Return the PQ payload size in bytes for this message direction.
	 * Called at registration time to cache sizes, and during receive
	 * validation. Must return a constant — cannot vary per-peer.
	 */
	u32 (*get_pq_payload_len)(bool is_initiation);

	/*
	 * Append PQ fields to an outgoing message.
	 * Called after classical Noise IK steps are complete and the
	 * classical fields are written to the buffer.
	 *
	 * @handshake:      the peer's noise handshake (for chaining_key/hash)
	 * @pq_buf:         buffer at the start of the PQ payload area
	 * @pq_buf_len:     bytes available (== get_pq_payload_len result)
	 * @peer:           the peer
	 * @is_initiation:  true for initiation, false for response
	 *
	 * Return 0 on success, negative errno on failure (aborts handshake).
	 */
	int (*append_pq)(struct noise_handshake *handshake,
			 u8 *pq_buf, u32 pq_buf_len,
			 struct wg_peer *peer,
			 bool is_initiation);

	/*
	 * Consume PQ fields from an incoming message.
	 * Called after classical Noise IK consume steps are complete
	 * and the peer has been identified.
	 *
	 * @handshake:      the peer's noise handshake
	 * @pq_buf:         PQ payload from the received message
	 * @pq_buf_len:     bytes (already validated against cached size)
	 * @peer:           the identified peer
	 * @is_initiation:  true for initiation, false for response
	 *
	 * Return 0 on success, negative errno on failure (aborts handshake).
	 */
	int (*consume_pq)(struct noise_handshake *handshake,
			  const u8 *pq_buf, u32 pq_buf_len,
			  struct wg_peer *peer,
			  bool is_initiation);

	/*
	 * Netlink: set PQC attributes on a peer.
	 * Called from set_peer() when any WGPEER_A_PQC_* attributes
	 * are present. The extension owns key parsing, validation,
	 * and storage. WireGuard passes the raw nlattrs through.
	 *
	 * @peer:   the peer being configured
	 * @attrs:  parsed nlattr array (extension reads PQC-specific indices)
	 *
	 * Return 0 on success, negative errno on failure.
	 * Optional — NULL if the extension doesn't need per-peer config.
	 */
	int (*nl_set_peer)(struct wg_peer *peer, struct nlattr **attrs);

	/*
	 * Path-based key loading. The PQC extension reads the key files
	 * directly from the filesystem using kernel_read_file_from_path().
	 * Paths are passed as NLA_NUL_STRING via netlink.
	 */
	int (*set_peer_key_from_path)(struct wg_peer *peer, const char *path);
	int (*set_device_keys_from_path)(struct wg_device *wg,
					 const char *sk_path,
					 const char *pk_path);

	/*
	 * Netlink: get PQC attributes from a peer.
	 * Called from get_peer() to serialize PQC state into the response.
	 *
	 * @peer:   the peer
	 * @skb:    netlink message being built (use nla_put to append)
	 *
	 * Return 0 on success, negative errno on failure.
	 * Optional — NULL if nothing to report.
	 */
	int (*nl_get_peer)(struct wg_peer *peer, struct sk_buff *skb);

	/*
	 * Netlink: set PQC attributes on the device.
	 * Called from set_device() when WGDEVICE_A_PQC_PRIVATE_KEY is
	 * present. The extension owns device-level key storage.
	 *
	 * @wg:     the WireGuard device
	 * @attrs:  parsed nlattr array
	 *
	 * Return 0 on success, negative errno on failure.
	 * Optional — NULL if no device-level config needed.
	 */
	int (*nl_set_device)(struct wg_device *wg, struct nlattr **attrs);

	/*
	 * Netlink: get PQC attributes from the device.
	 * Called from get_device() to serialize device-level PQC state.
	 *
	 * @wg:     the WireGuard device
	 * @skb:    netlink message being built
	 *
	 * Return 0 on success, negative errno on failure.
	 * Optional — NULL if nothing to report.
	 */
	int (*nl_get_device)(struct wg_device *wg, struct sk_buff *skb);

	/*
	 * Cleanup: called when a peer is removed.
	 * The extension should free any per-peer PQC data it allocated.
	 * Optional — NULL if no cleanup needed.
	 */
	void (*peer_remove)(struct wg_peer *peer);

	/*
	 * Cleanup: called when a WireGuard device is destroyed.
	 * The extension should free any per-device PQC data it allocated
	 * (e.g. device keys stored in wg->pqc_device_data).
	 * Optional — NULL if no cleanup needed.
	 */
	void (*device_remove)(struct wg_device *wg);

	struct module *owner;
};

/* Static key — when false, all PQC code paths are NOPs */
extern struct static_key_false wg_pqc_enabled;

/* Current registered PQC ops — RCU-protected, read with rcu_dereference() */
extern struct wg_pqc_ops __rcu *wg_pqc_current;

/* Cached message sizes — set at registration, read in hot path */
extern u32 wg_pqc_init_payload_len;
extern u32 wg_pqc_resp_payload_len;
extern u32 wg_pqc_init_msg_len;
extern u32 wg_pqc_resp_msg_len;

int wg_pqc_register(struct wg_pqc_ops *ops);
void wg_pqc_unregister(struct wg_pqc_ops *ops);

/* Called from send.c */
void wg_pqc_send_handshake_initiation(struct wg_peer *peer);
void wg_pqc_send_handshake_response(struct wg_peer *peer);

/* Called from receive.c — returns the identified peer, or NULL */
struct wg_peer *wg_pqc_consume_initiation(struct wg_device *wg,
					   struct sk_buff *skb);
struct wg_peer *wg_pqc_consume_response(struct wg_device *wg,
					  struct sk_buff *skb);

/*
 * Noise primitive helpers for PQC extension modules.
 * These allow extensions to evolve the Noise symmetric state (hash,
 * chaining_key) without knowing the noise_handshake struct layout.
 * The handshake pointer is opaque to the extension — it must only
 * be passed to these helpers, never dereferenced.
 */
void wg_noise_hs_mix_hash(struct noise_handshake *hs,
			   const u8 *data, u32 len);
void wg_noise_hs_mix_key(struct noise_handshake *hs,
			  const u8 *data, u32 len);
void wg_noise_hs_kdf2(struct noise_handshake *hs, u8 key[32],
		       const u8 *input, u32 input_len);
void wg_noise_hs_encrypt_and_hash(struct noise_handshake *hs,
				   u8 *ct, const u8 *pt, u32 pt_len,
				   u8 key[32]);
bool wg_noise_hs_decrypt_and_hash(struct noise_handshake *hs,
				   u8 *pt, const u8 *ct, u32 ct_len,
				   u8 key[32]);
void *wg_noise_hs_get_scratch(struct noise_handshake *hs);
void wg_noise_hs_set_scratch(struct noise_handshake *hs,
			      void *scratch, u32 len);

#endif /* _WG_PQC_H */
