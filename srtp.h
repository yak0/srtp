#ifndef SRTP_H
#define SRTP_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sys/time.h>

/* 
 * SRTP Constants as defined in RFC 3711
 */
#define SRTP_MASTER_KEY_LEN        16  // 128 bits
#define SRTP_MASTER_SALT_LEN       14  // 112 bits
#define SRTP_SESSION_KEY_LEN       16  // 128 bits
#define SRTP_SESSION_SALT_LEN      14  // 112 bits
#define SRTP_SESSION_AUTH_KEY_LEN  20  // 160 bits
#define SRTP_AUTH_TAG_LEN          10  // 80 bits (truncated from 160 bits)
#define SRTP_MAX_TRAILER_LEN       SRTP_AUTH_TAG_LEN
#define SRTP_WINDOW_SIZE           64  // 64-bit sliding window for replay protection
#define SRTP_GCM_TAG_LEN           16  // 128 bits
#define SRTP_GCM_SALT_LEN          12  // 96 bits
#define SRTP_MKI_MAX_LEN           128 // Maximum MKI length

/* 
 * Cipher and authentication algorithm labels for key derivation 
 */
#define SRTP_ENCRYPTION_LABEL      0x00
#define SRTP_AUTHENTICATION_LABEL  0x01
#define SRTP_SALT_LABEL            0x02

/* 
 * Return codes for SRTP operations
 */
typedef enum {
    SRTP_SUCCESS = 0,
    SRTP_FAIL_INIT,
    SRTP_FAIL_KEY_DERIVATION,
    SRTP_FAIL_ENCRYPTION,
    SRTP_FAIL_DECRYPTION,
    SRTP_FAIL_AUTHENTICATION,
    SRTP_FAIL_REPLAY,
    SRTP_FAIL_NULL_ARG,
    SRTP_FAIL_PACKET_TOO_SMALL,
    SRTP_FAIL_PACKET_TOO_LARGE,
    SRTP_FAIL_MKI,
    SRTP_FAIL_ALLOC,
    SRTP_FAIL_BUFFER_TOO_SMALL,
    SRTP_FAIL_DUPLICATE_SSRC,
    SRTP_FAIL_UNKNOWN_SSRC,
    SRTP_FAIL_CONFERENCE_FULL,
    SRTP_FAIL_JITTER_BUFFER_FULL,
    SRTP_FAIL_JITTER_BUFFER_EMPTY,
    SRTP_FAIL_CIPHER_MODE
} srtp_err_status_t;

/*
 * SRTP context structure
 * Contains keys and state needed for SRTP cryptographic operations
 */
typedef struct {
    /* Master keys */
    uint8_t master_key[SRTP_MASTER_KEY_LEN];
    uint8_t master_salt[SRTP_MASTER_SALT_LEN];
    
    /* Session keys - derived from master keys */
    uint8_t session_key[SRTP_SESSION_KEY_LEN];
    uint8_t session_salt[SRTP_SESSION_SALT_LEN];
    uint8_t session_auth_key[SRTP_SESSION_AUTH_KEY_LEN];
    
    /* OpenSSL context for AES operations */
    AES_KEY aes_key;
    bool use_aes_gcm;
    
    /* Replay protection */
    uint64_t replay_window; // Bitmap for replay protection
    uint32_t roc;           // Roll-over counter
    uint16_t s_l;           // Highest sequence number received
    
    /* Configuration */
    bool use_mki;           // Whether to use MKI (Master Key Identifier)
    uint8_t mki_len;        // Length of MKI
    uint8_t mki[SRTP_MKI_MAX_LEN]; // MKI value (up to 128 bytes)
} srtp_ctx_t;

/*
 * Function prototypes
 */
srtp_err_status_t srtp_init(srtp_ctx_t *ctx, const uint8_t *key, const uint8_t *salt);
srtp_err_status_t srtp_derive_keys(srtp_ctx_t *ctx);
srtp_err_status_t srtp_protect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len, size_t max_len);
srtp_err_status_t srtp_unprotect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len);
srtp_err_status_t srtp_generate_keys(uint8_t *key, size_t key_len, uint8_t *salt, size_t salt_len);
srtp_err_status_t srtp_update_rollover_counter(srtp_ctx_t *ctx, uint16_t seq);
bool srtp_check_replay(srtp_ctx_t *ctx, uint16_t seq);
void srtp_update_replay_window(srtp_ctx_t *ctx, uint16_t seq);

#endif /* SRTP_H */