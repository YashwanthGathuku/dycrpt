/**
 * VoiceChat Crypto — stable C ABI for Android / iOS.
 *
 * SECURITY: Never interpret handles as pointers to key material.
 * Raw root/chain/message/identity/ML-KEM private keys and PQXDH
 * shared secrets are not exported. Handshake runs inside the engine.
 */

#ifndef VOICECHAT_CRYPTO_H
#define VOICECHAT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t VcHandle;

typedef enum {
  VC_OK = 0,
  VC_INVALID_ARGUMENT = 1,
  VC_CRYPTO_FAILURE = 2,
  VC_STATE_ERROR = 3,
  VC_NOT_FOUND = 4,
  VC_IDENTITY_CHANGED = 5,
  VC_LIMIT_EXCEEDED = 6,
  /* Persisted state is authentic but older than the rollback anchor.
   * TERMINAL. Never retry, never fall back to a fresh-device constructor,
   * never resolve silently. See vc_engine_open_persistent. */
  VC_ROLLBACK_DETECTED = 7,
  /* Persisted state missing/unreadable while the anchor shows the device was
   * previously provisioned. Also terminal. */
  VC_STATE_LOST = 8,
  /* The supplied rollback anchor could not be read or advanced. */
  VC_ANCHOR_UNAVAILABLE = 9,
  /* No persisted state and a pristine anchor: never provisioned. The only
   * non-terminal open failure — call with create_if_absent = 1. */
  VC_NOT_INITIALIZED = 10,
  VC_INTERNAL = 99
} VcError;

/**
 * Rollback-resistant monotonic anchor supplied by the host platform.
 *
 * The anchor MUST live outside the application's restorable data domain. A row
 * in the same database as the state file, or a file beside it, does NOT
 * satisfy the contract: both are restored together with the state they are
 * meant to validate.
 *
 * Both callbacks return 0 on success, non-zero on failure, and write through
 * the out-pointer only on success.
 *
 * compare_and_increment MUST have resolved whether the value changed before
 * returning an error. An outcome that can remain unknown is not compatible with
 * this interface: an unobserved advance desynchronizes the durable epoch and is
 * indistinguishable from a rollback on the next open.
 *
 * ctx and both callbacks must remain valid for the lifetime of the engine
 * handle and MUST be safe to call from multiple threads simultaneously.
 * Callbacks must not unwind across the boundary.
 */
typedef struct {
  void *ctx;
  int32_t (*current)(void *ctx, uint64_t *out);
  int32_t (*compare_and_increment)(void *ctx, uint64_t expected, uint64_t *out);
} VcRollbackAnchorCallbacks;

uint16_t vc_protocol_version(void);

int32_t vc_engine_create(
    const uint8_t *device_id, size_t device_id_len,
    uint8_t profile,
    VcHandle *out_handle,
    uint8_t *out_public /* 32 bytes, nullable */);

int32_t vc_create_device_identity(
    const uint8_t *device_id, size_t device_id_len,
    VcHandle *out_handle,
    uint8_t *out_public /* 32 bytes, nullable */);

/**
 * Open a PERSISTENT engine backed by encrypted on-disk storage.
 * This is the production constructor; vc_engine_create is development-only
 * in-memory storage and loses everything on process exit.
 *
 * create_if_absent:
 *   0 = restore an existing device.
 *   1 = provision a new device. Refuses unless the anchor is pristine and no
 *       state exists, so it CANNOT be used to paper over a failed restore.
 *
 * storage_key is 32 bytes; it is copied and the copy zeroized before return.
 *
 * On VC_ROLLBACK_DETECTED or VC_STATE_LOST this refuses and there is
 * deliberately NO library-provided recovery call. Retrying, or calling again
 * with create_if_absent = 1, is not a recovery path and will not succeed.
 */
int32_t vc_engine_open_persistent(
    const uint8_t *device_id, size_t device_id_len,
    uint8_t profile,
    const uint8_t *path, size_t path_len,
    const uint8_t *storage_key /* 32 bytes */,
    VcRollbackAnchorCallbacks anchor,
    uint8_t create_if_absent,
    VcHandle *out_handle,
    uint8_t *out_public /* 32 bytes, nullable */);

int32_t vc_engine_destroy(VcHandle engine);
int32_t vc_delete_identity(VcHandle identity);

int32_t vc_engine_public_identity(VcHandle engine, uint8_t *out_public /* 32 */);

int32_t vc_generate_bundle(
    VcHandle engine,
    size_t one_time_count,
    uint8_t *out, size_t *out_len);

int32_t vc_establish_outbound(
    VcHandle engine,
    const uint8_t *bundle, size_t bundle_len,
    const uint8_t *conversation, size_t conversation_len,
    const uint8_t *first_pt, size_t first_pt_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *out_session /* 16 */,
    uint8_t *out_packet, size_t *out_packet_len);

int32_t vc_process_inbound(
    VcHandle engine,
    const uint8_t *packet, size_t packet_len,
    const uint8_t *conversation, size_t conversation_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *out_session /* 16 */,
    uint8_t *out_pt, size_t *out_pt_len);

int32_t vc_encrypt(
    VcHandle engine,
    const uint8_t *session_id /* 16 */,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *out, size_t *out_len);

int32_t vc_decrypt(
    VcHandle engine,
    const uint8_t *session_id /* 16 */,
    const uint8_t *sealed, size_t sealed_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *out_pt, size_t *out_pt_len);

int32_t vc_fingerprint(
    const uint8_t *public_a, const uint8_t *public_b,
    const uint8_t *device_a, size_t device_a_len,
    const uint8_t *device_b, size_t device_b_len,
    uint8_t *out_binary,               /* 32 */
    uint8_t *out_numeric, size_t *out_numeric_len);

int32_t vc_delete_session(VcHandle engine, const uint8_t *session_id /* 16 */);

#ifdef __cplusplus
}
#endif

#endif /* VOICECHAT_CRYPTO_H */
