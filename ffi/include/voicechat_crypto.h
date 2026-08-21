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
  VC_INTERNAL = 99
} VcError;

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
