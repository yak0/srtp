#include "srtp.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>  // For network byte order conversions

/*
 * RTP header structure definition (12 bytes fixed header)
 */
typedef struct {
    uint8_t  version_p_x_cc;   // Version(2), Padding(1), Extension(1), CSRC count(4)
    uint8_t  marker_pt;        // Marker(1), Payload Type(7)
    uint16_t seq;              // Sequence number
    uint32_t timestamp;        // Timestamp
    uint32_t ssrc;             // Synchronization Source identifier
    // CSRC list and extensions would follow here in actual RTP packet
} rtp_header_t;

/*
 * Initialize an SRTP context with master key and salt
 */
srtp_err_status_t srtp_init(srtp_ctx_t *ctx, const uint8_t *key, const uint8_t *salt) {
    if (!ctx || !key || !salt) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    // Initialize context to zero
    memset(ctx, 0, sizeof(srtp_ctx_t));
    
    // Copy master key and salt
    memcpy(ctx->master_key, key, SRTP_MASTER_KEY_LEN);
    memcpy(ctx->master_salt, salt, SRTP_MASTER_SALT_LEN);
    
    // Initialize replay protection
    ctx->replay_window = 0;
    ctx->roc = 0;
    ctx->s_l = 0;
    
    // Default - no MKI
    ctx->use_mki = false;
    ctx->mki_len = 0;
    
    // Derive session keys from master key and salt
    return srtp_derive_keys(ctx);
}

/*
 * Key Derivation Function (KDF) as specified in RFC 3711
 * Simplified version that uses AES-CM PRF
 */
srtp_err_status_t srtp_derive_keys(srtp_ctx_t *ctx) {
    if (!ctx) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    uint8_t label;
    uint8_t x[16]; // 128-bit block for AES input
    uint8_t iv[16]; // Initialization Vector
    uint8_t key_id[7]; // Used in PRF calculations
    AES_KEY aes_ctx;
    
    // Initialize key_id with first 6 bytes of salt followed by a zero byte
    memcpy(key_id, ctx->master_salt, 6);
    key_id[6] = 0x00;
    
    // Set up AES key for key derivation
    if (AES_set_encrypt_key(ctx->master_key, 128, &aes_ctx) < 0) {
        return SRTP_FAIL_KEY_DERIVATION;
    }
    
    // Derive session encryption key
    label = SRTP_ENCRYPTION_LABEL;
    memset(iv, 0, sizeof(iv));
    memcpy(iv, key_id, 7);
    iv[7] = label;
    
    // Use AES in Counter Mode as PRF
    memset(x, 0, sizeof(x));
    AES_encrypt(iv, x, &aes_ctx);
    memcpy(ctx->session_key, x, SRTP_SESSION_KEY_LEN);
    
    // Derive session authentication key
    label = SRTP_AUTHENTICATION_LABEL;
    memset(iv, 0, sizeof(iv));
    memcpy(iv, key_id, 7);
    iv[7] = label;
    
    memset(x, 0, sizeof(x));
    AES_encrypt(iv, x, &aes_ctx);
    
    // HMAC-SHA1 key is 160 bits (20 bytes), so we need to generate 
    // more than one block for the auth key
    uint8_t x2[16];
    iv[15] = 1; // Increment counter
    AES_encrypt(iv, x2, &aes_ctx);
    
    memcpy(ctx->session_auth_key, x, 16);
    memcpy(ctx->session_auth_key + 16, x2, SRTP_SESSION_AUTH_KEY_LEN - 16);
    
    // Derive session salt
    label = SRTP_SALT_LABEL;
    memset(iv, 0, sizeof(iv));
    memcpy(iv, key_id, 7);
    iv[7] = label;
    
    memset(x, 0, sizeof(x));
    AES_encrypt(iv, x, &aes_ctx);
    memcpy(ctx->session_salt, x, SRTP_SESSION_SALT_LEN);
    
    // Initialize AES context with session key for packet encryption
    if (AES_set_encrypt_key(ctx->session_key, 128, &ctx->aes_key) < 0) {
        return SRTP_FAIL_KEY_DERIVATION;
    }
    
    return SRTP_SUCCESS;
}

/*
 * Generate initialization vector for AES-CM encryption
 * IV = (salt XOR (ssrc | roc | seq | 0x0000)) 
 */
static void srtp_calculate_iv(uint8_t *iv, uint8_t *session_salt, 
                             uint32_t ssrc, uint32_t roc, uint16_t seq) {
    // Start with all zeros
    memset(iv, 0, 16);
    
    // Format: SSRC || ROC || SEQ || 0x0000
    iv[0] = (ssrc >> 24) & 0xFF;
    iv[1] = (ssrc >> 16) & 0xFF;
    iv[2] = (ssrc >> 8) & 0xFF;
    iv[3] = ssrc & 0xFF;
    
    iv[4] = (roc >> 24) & 0xFF;
    iv[5] = (roc >> 16) & 0xFF;
    iv[6] = (roc >> 8) & 0xFF;
    iv[7] = roc & 0xFF;
    
    iv[8] = (seq >> 8) & 0xFF;
    iv[9] = seq & 0xFF;
    
    // XOR with session salt (first 14 bytes)
    for (int i = 0; i < SRTP_SESSION_SALT_LEN; i++) {
        iv[i] ^= session_salt[i];
    }
}

/*
 * Encrypt RTP payload using AES Counter Mode
 */
static srtp_err_status_t srtp_encrypt_payload(srtp_ctx_t *ctx, 
                                             uint8_t *payload, size_t payload_len,
                                             uint32_t ssrc, uint32_t roc, uint16_t seq) {
    uint8_t iv[16], counter[16], keystream[16];
    uint8_t *p = payload;
    size_t bytes_to_encrypt = payload_len;
    int block, partial;
    
    // Calculate initial IV
    srtp_calculate_iv(iv, ctx->session_salt, ssrc, roc, seq);
    
    // Start counter at offset zero
    memcpy(counter, iv, 16);
    
    // Encrypt full blocks with AES-CM
    block = 0;
    while (bytes_to_encrypt >= 16) {
        // Update counter for this block
        counter[15] = (iv[15] + block) & 0xFF;
        
        // Generate keystream block
        AES_encrypt(counter, keystream, &ctx->aes_key);
        
        // XOR with plaintext to produce ciphertext
        for (int i = 0; i < 16; i++) {
            p[i] ^= keystream[i];
        }
        
        p += 16;
        bytes_to_encrypt -= 16;
        block++;
    }
    
    // Handle partial block if any
    if (bytes_to_encrypt > 0) {
        counter[15] = (iv[15] + block) & 0xFF;
        AES_encrypt(counter, keystream, &ctx->aes_key);
        
        for (int i = 0; i < bytes_to_encrypt; i++) {
            p[i] ^= keystream[i];
        }
    }
    
    return SRTP_SUCCESS;
}

/*
 * Calculate authentication tag for SRTP packet
 */
static void srtp_calculate_auth_tag(srtp_ctx_t *ctx, const uint8_t *packet, size_t packet_len,
                                   uint32_t roc, uint8_t *tag) {
    uint8_t roc_buffer[4];
    unsigned int hmac_len;
    
    // Initialize HMAC-SHA1 context
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, ctx->session_auth_key, SRTP_SESSION_AUTH_KEY_LEN, EVP_sha1(), NULL);
    
    // Add RTP packet to HMAC
    HMAC_Update(hmac_ctx, packet, packet_len);
    
    // Add ROC to HMAC
    roc_buffer[0] = (roc >> 24) & 0xFF;
    roc_buffer[1] = (roc >> 16) & 0xFF;
    roc_buffer[2] = (roc >> 8) & 0xFF;
    roc_buffer[3] = roc & 0xFF;
    HMAC_Update(hmac_ctx, roc_buffer, 4);
    
    // Finalize and get the authentication tag (truncated to 80 bits)
    uint8_t hmac_output[20]; // SHA1 produces 160 bits (20 bytes)
    HMAC_Final(hmac_ctx, hmac_output, &hmac_len);
    HMAC_CTX_free(hmac_ctx);
    
    // Copy first SRTP_AUTH_TAG_LEN bytes as the authentication tag
    memcpy(tag, hmac_output, SRTP_AUTH_TAG_LEN);
}

/*
 * Update the ROC (Roll-Over Counter) when sequence number wraps
 */
srtp_err_status_t srtp_update_rollover_counter(srtp_ctx_t *ctx, uint16_t seq) {
    // RFC 3711 logic for ROC update
    if (!ctx) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    if (ctx->s_l < 32768) {
        if (seq - ctx->s_l > 32768) {
            // Sequence number wrapped around
            ctx->roc--;
        }
    } else {
        if (ctx->s_l - 32768 > seq) {
            // Sequence number wrapped around
            ctx->roc++;
        }
    }
    
    ctx->s_l = seq;
    return SRTP_SUCCESS;
}

/*
 * Check if packet is a replay based on sequence number
 */
bool srtp_check_replay(srtp_ctx_t *ctx, uint16_t seq) {
    int diff, idx;
    
    if (ctx->s_l < seq) {
        diff = seq - ctx->s_l;
    } else {
        diff = ctx->s_l - seq;
    }
    
    if (diff >= SRTP_WINDOW_SIZE) {
        // Packet is too old, outside window
        return true;
    }
    
    idx = diff;
    if ((ctx->replay_window >> idx) & 1) {
        // Packet already received (bit is set)
        return true;
    }
    
    return false;
}

/*
 * Update replay window upon receiving a valid packet
 */
void srtp_update_replay_window(srtp_ctx_t *ctx, uint16_t seq) {
    int diff, idx;
    
    if (ctx->s_l < seq) {
        // New packet is ahead of highest seen
        diff = seq - ctx->s_l;
        ctx->replay_window = ctx->replay_window << diff;
        ctx->replay_window |= 1;  // Set bit for current packet
        ctx->s_l = seq;
    } else {
        // Older packet within window
        diff = ctx->s_l - seq;
        idx = diff;
        ctx->replay_window |= (1ULL << idx);  // Set bit for received packet
    }
}

/*
 * Generate random master key and salt using OpenSSL's RAND
 */
srtp_err_status_t srtp_generate_keys(uint8_t *key, size_t key_len, uint8_t *salt, size_t salt_len) {
    if (!key || !salt) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    // Generate cryptographically secure random numbers
    if (!RAND_bytes(key, key_len)) {
        return SRTP_FAIL_KEY_DERIVATION;
    }
    
    if (!RAND_bytes(salt, salt_len)) {
        return SRTP_FAIL_KEY_DERIVATION;
    }
    
    return SRTP_SUCCESS;
}

/*
 * Protect (encrypt and authenticate) an RTP packet
 */
srtp_err_status_t srtp_protect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len, size_t max_len) {
    if (!ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    size_t rtp_len = *packet_len;
    rtp_header_t *header = (rtp_header_t *)packet;
    uint16_t seq = ntohs(header->seq);
    uint32_t ssrc = ntohl(header->ssrc);
    
    // Calculate header extension size if present
    uint8_t *payload_start = packet + sizeof(rtp_header_t);
    if (header->version_p_x_cc & 0x10) {  // Extension bit (X) is set
        uint16_t ext_header_len;
        // Skip CSRCs if present
        uint8_t cc = header->version_p_x_cc & 0x0F;
        payload_start += cc * 4;
        
        // Extract extension header length (in 32-bit words)
        ext_header_len = ntohs(*(uint16_t *)(payload_start + 2));
        payload_start += 4 + (ext_header_len * 4);
    } else {
        // Skip CSRCs if present
        uint8_t cc = header->version_p_x_cc & 0x0F;
        payload_start += cc * 4;
    }
    
    size_t header_len = payload_start - packet;
    size_t payload_len = rtp_len - header_len;
    
    // Ensure packet has enough space for authentication tag
    if (max_len < rtp_len + SRTP_AUTH_TAG_LEN + (ctx->use_mki ? ctx->mki_len : 0)) {
        return SRTP_FAIL_PACKET_TOO_LARGE;
    }
    
    // Encrypt the payload using AES Counter Mode
    srtp_encrypt_payload(ctx, payload_start, payload_len, ssrc, ctx->roc, seq);
    
    // Add MKI if needed
    if (ctx->use_mki) {
        memcpy(packet + rtp_len, ctx->mki, ctx->mki_len);
        rtp_len += ctx->mki_len;
    }
    
    // Calculate and append authentication tag
    srtp_calculate_auth_tag(ctx, packet, rtp_len, ctx->roc, packet + rtp_len);
    *packet_len = rtp_len + SRTP_AUTH_TAG_LEN;
    
    return SRTP_SUCCESS;
}

/*
 * Unprotect (verify and decrypt) an SRTP packet
 */
srtp_err_status_t srtp_unprotect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len) {
    if (!ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    size_t srtcp_packet_len = *packet_len;
    
    // Ensure packet is large enough for RTP header + auth tag
    if (srtcp_packet_len < sizeof(rtp_header_t) + SRTP_AUTH_TAG_LEN) {
        return SRTP_FAIL_PACKET_TOO_SMALL;
    }
    
    rtp_header_t *header = (rtp_header_t *)packet;
    uint16_t seq = ntohs(header->seq);
    uint32_t ssrc = ntohl(header->ssrc);
    uint32_t roc = ctx->roc;  // Use current ROC
    
    // Determine lengths for verification
    size_t mki_len = ctx->use_mki ? ctx->mki_len : 0;
    size_t auth_tag_offset = srtcp_packet_len - SRTP_AUTH_TAG_LEN;
    size_t auth_len = auth_tag_offset - mki_len;
    
    // Verify MKI if used
    if (ctx->use_mki) {
        if (memcmp(packet + auth_len, ctx->mki, mki_len) != 0) {
            return SRTP_FAIL_MKI;
        }
    }
    
    // Check for replay attack
    if (srtp_check_replay(ctx, seq)) {
        return SRTP_FAIL_REPLAY;
    }
    
    // Compute authentication tag and verify
    uint8_t calculated_tag[SRTP_AUTH_TAG_LEN];
    srtp_calculate_auth_tag(ctx, packet, auth_len, roc, calculated_tag);
    
    // Constant-time comparison to prevent timing attacks
    int tag_match = 1;
    for (int i = 0; i < SRTP_AUTH_TAG_LEN; i++) {
        tag_match &= (calculated_tag[i] == packet[auth_tag_offset + i]);
    }
    
    if (!tag_match) {
        return SRTP_FAIL_AUTHENTICATION;
    }
    
    // Authentication passed, update ROC if needed
    srtp_update_rollover_counter(ctx, seq);
    
    // Update replay window
    srtp_update_replay_window(ctx, seq);
    
    // Calculate header extension size and find payload start
    uint8_t *payload_start = packet + sizeof(rtp_header_t);
    if (header->version_p_x_cc & 0x10) {  // Extension bit (X) is set
        uint16_t ext_header_len;
        // Skip CSRCs if present
        uint8_t cc = header->version_p_x_cc & 0x0F;
        payload_start += cc * 4;
        
        // Extract extension header length (in 32-bit words)
        ext_header_len = ntohs(*(uint16_t *)(payload_start + 2));
        payload_start += 4 + (ext_header_len * 4);
    } else {
        // Skip CSRCs if present
        uint8_t cc = header->version_p_x_cc & 0x0F;
        payload_start += cc * 4;
    }
    
    size_t header_len = payload_start - packet;
    size_t payload_len = auth_len - header_len - mki_len;
    
    // Decrypt the payload using AES Counter Mode
    srtp_encrypt_payload(ctx, payload_start, payload_len, ssrc, roc, seq);
    
    // Remove authentication tag and MKI from packet length
    *packet_len = auth_len;
    
    return SRTP_SUCCESS;
}

/*
 * SRTCP functions for secure RTCP processing
 */

/*
 * Protect RTCP packet
 */
srtp_err_status_t srtcp_protect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len, size_t max_len) {
    if (!ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    // Ensure packet is large enough
    if (*packet_len < 8) {  // Minimum RTCP header size
        return SRTP_FAIL_PACKET_TOO_SMALL;
    }
    
    // Ensure we have enough space for E-bit, index, and auth tag
    if (max_len < *packet_len + 4 + SRTP_AUTH_TAG_LEN + (ctx->use_mki ? ctx->mki_len : 0)) {
        return SRTP_FAIL_PACKET_TOO_LARGE;
    }
    
    size_t rtcp_len = *packet_len;
    uint32_t ssrc;
    
    // Extract SSRC from RTCP header (at offset 4)
    memcpy(&ssrc, packet + 4, 4);
    ssrc = ntohl(ssrc);
    
    // Encrypt RTCP payload (everything after first 8 bytes)
    if (rtcp_len > 8) {
        srtp_encrypt_payload(ctx, packet + 8, rtcp_len - 8, ssrc, ctx->rtcp_index, 0);
    }
    
    // Add encryption flag (E) and 31-bit SRTCP index at end of packet
    uint32_t e_and_index = htonl(0x80000000 | ctx->rtcp_index);
    memcpy(packet + rtcp_len, &e_and_index, 4);
    rtcp_len += 4;
    
    // Add MKI if needed
    if (ctx->use_mki) {
        memcpy(packet + rtcp_len, ctx->mki, ctx->mki_len);
        rtcp_len += ctx->mki_len;
    }
    
    // Calculate and append authentication tag
    srtcp_calculate_auth_tag(ctx, packet, rtcp_len, packet + rtcp_len);
    *packet_len = rtcp_len + SRTP_AUTH_TAG_LEN;
    
    // Increment SRTCP index for next packet
    ctx->rtcp_index++;
    
    return SRTP_SUCCESS;
}

/*
 * Calculate authentication tag for SRTCP packet
 */
static void srtcp_calculate_auth_tag(srtp_ctx_t *ctx, const uint8_t *packet, 
                                    size_t packet_len, uint8_t *tag) {
    unsigned int hmac_len;
    
    // Initialize HMAC-SHA1 context
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, ctx->session_auth_key, SRTP_SESSION_AUTH_KEY_LEN, EVP_sha1(), NULL);
    
    // Add RTCP packet to HMAC
    HMAC_Update(hmac_ctx, packet, packet_len);
    
    // Finalize and get the authentication tag (truncated to 80 bits)
    uint8_t hmac_output[20]; // SHA1 produces 160 bits (20 bytes)
    HMAC_Final(hmac_ctx, hmac_output, &hmac_len);
    HMAC_CTX_free(hmac_ctx);
    
    // Copy first SRTP_AUTH_TAG_LEN bytes as the authentication tag
    memcpy(tag, hmac_output, SRTP_AUTH_TAG_LEN);
}

/*
 * Unprotect SRTCP packet
 */
srtp_err_status_t srtcp_unprotect(srtp_ctx_t *ctx, uint8_t *packet, size_t *packet_len) {
    if (!ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    size_t srtcp_packet_len = *packet_len;
    
    // Ensure packet is large enough for RTCP header + E/Index + auth tag
    if (srtcp_packet_len < 8 + 4 + SRTP_AUTH_TAG_LEN) {
        return SRTP_FAIL_PACKET_TOO_SMALL;
    }
    
    // Determine lengths for verification
    size_t mki_len = ctx->use_mki ? ctx->mki_len : 0;
    size_t auth_tag_offset = srtcp_packet_len - SRTP_AUTH_TAG_LEN;
    size_t e_index_offset = auth_tag_offset - mki_len - 4;
    size_t rtcp_content_len = e_index_offset;
    
    // Verify MKI if used
    if (ctx->use_mki) {
        if (memcmp(packet + e_index_offset + 4, ctx->mki, mki_len) != 0) {
            return SRTP_FAIL_MKI;
        }
    }
    
    // Compute authentication tag and verify
    uint8_t calculated_tag[SRTP_AUTH_TAG_LEN];
    srtcp_calculate_auth_tag(ctx, packet, auth_tag_offset - mki_len, calculated_tag);
    
    // Constant-time comparison to prevent timing attacks
    int tag_match = 1;
    for (int i = 0; i < SRTP_AUTH_TAG_LEN; i++) {
        tag_match &= (calculated_tag[i] == packet[auth_tag_offset + i]);
    }
    
    if (!tag_match) {
        return SRTP_FAIL_AUTHENTICATION;
    }
    
    // Extract E flag and SRTCP index
    uint32_t e_and_index;
    memcpy(&e_and_index, packet + e_index_offset, 4);
    e_and_index = ntohl(e_and_index);
    
    // Check E flag (encryption bit)
    int encrypted = (e_and_index & 0x80000000) != 0;
    uint32_t index = e_and_index & 0x7FFFFFFF;
    
    // Check for replay (simplified version - in production would use a window like RTP)
    if (index <= ctx->rtcp_index_received && ctx->rtcp_index_received > 0) {
        return SRTP_FAIL_REPLAY;
    }
    ctx->rtcp_index_received = index;
    
    // Decrypt if needed
    if (encrypted) {
        uint32_t ssrc;
        memcpy(&ssrc, packet + 4, 4);
        ssrc = ntohl(ssrc);
        
        // Decrypt RTCP payload (everything after first 8 bytes)
        if (rtcp_content_len > 8) {
            srtp_encrypt_payload(ctx, packet + 8, rtcp_content_len - 8, ssrc, index, 0);
        }
    }
    
    // Remove E/index, MKI, and auth tag
    *packet_len = rtcp_content_len;
    
    return SRTP_SUCCESS;
}

/*
 * DTLS-SRTP key derivation (extract keys from DTLS handshake)
 */
srtp_err_status_t srtp_derive_keys_from_dtls(srtp_ctx_t *ctx, 
                                         const uint8_t *material, size_t material_len) {
    if (!ctx || !material || material_len < 60) {
        return SRTP_FAIL_NULL_ARG;
    }

    // Extract client_write_key (16 bytes) and client_write_salt (14 bytes)
    memcpy(ctx->master_key, material, SRTP_MASTER_KEY_LEN);
    memcpy(ctx->master_salt, material + SRTP_MASTER_KEY_LEN, SRTP_MASTER_SALT_LEN);

    // Derive session keys
    return srtp_derive_keys(ctx);
}

/*
 * GCM mode support (AES-GCM as defined in RFC 7714)
 */
srtp_err_status_t srtp_set_aes_gcm_mode(srtp_ctx_t *ctx, bool enable) {
    if (!ctx) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    ctx->use_aes_gcm = enable;
    
    // Reset any existing crypto state
    return srtp_derive_keys(ctx);
}

/*
 * Protect using AES-GCM (more efficient than AES-CM + HMAC)
 */
static srtp_err_status_t srtp_protect_gcm(srtp_ctx_t *ctx, uint8_t *packet, 
                                        size_t *packet_len, size_t max_len) {
    if (!ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    size_t rtp_len = *packet_len;
    rtp_header_t *header = (rtp_header_t *)packet;
    uint16_t seq = ntohs(header->seq);
    uint32_t ssrc = ntohl(header->ssrc);
    
    // Calculate header length and find payload start
    uint8_t *payload_start = packet + sizeof(rtp_header_t);
    size_t header_len = sizeof(rtp_header_t);
    
    // Handle CSRC and extension headers
    if (header->version_p_x_cc & 0x0F) { // CSRC count
        uint8_t cc = header->version_p_x_cc & 0x0F;
        payload_start += cc * 4;
        header_len += cc * 4;
    }
    
    if (header->version_p_x_cc & 0x10) {  // Extension bit
        uint16_t ext_len = ntohs(*(uint16_t *)(payload_start + 2)) * 4 + 4;
        payload_start += ext_len;
        header_len += ext_len;
    }
    
    size_t payload_len = rtp_len - header_len;
    
    // Ensure packet has enough space for auth tag
    size_t tag_len = ctx->use_aes_gcm ? SRTP_GCM_TAG_LEN : SRTP_AUTH_TAG_LEN;
    if (max_len < rtp_len + tag_len + (ctx->use_mki ? ctx->mki_len : 0)) {
        return SRTP_FAIL_PACKET_TOO_LARGE;
    }
    
    // Prepare AAD (Additional Authenticated Data) - the RTP header
    EVP_CIPHER_CTX *gcm_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    
    // Set IV
    uint8_t iv[12]; // GCM uses 96-bit IV
    srtp_calculate_gcm_iv(iv, ctx->session_salt, ssrc, ctx->roc, seq);
    EVP_EncryptInit_ex(gcm_ctx, NULL, NULL, ctx->session_key, iv);
    
    // Add RTP header as AAD
    int len;
    EVP_EncryptUpdate(gcm_ctx, NULL, &len, packet, header_len);
    
    // Encrypt payload in-place
    EVP_EncryptUpdate(gcm_ctx, payload_start, &len, payload_start, payload_len);
    
    // Finalize
    EVP_EncryptFinal_ex(gcm_ctx, NULL, &len);
    
    // Get authentication tag
    EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_GET_TAG, SRTP_GCM_TAG_LEN, 
                        packet + rtp_len + (ctx->use_mki ? ctx->mki_len : 0));
    EVP_CIPHER_CTX_free(gcm_ctx);
    
    // Add MKI if needed
    if (ctx->use_mki) {
        memcpy(packet + rtp_len, ctx->mki, ctx->mki_len);
        rtp_len += ctx->mki_len;
    }
    
    *packet_len = rtp_len + SRTP_GCM_TAG_LEN;
    
    return SRTP_SUCCESS;
}

/*
 * Calculate IV for AES-GCM mode (RFC 7714)
 */
static void srtp_calculate_gcm_iv(uint8_t *iv, uint8_t *session_salt, 
                                uint32_t ssrc, uint32_t roc, uint16_t seq) {
    // Format: salt XOR (0x00 || 0x00 || ssrc || roc || seq)
    memset(iv, 0, 12);
    
    // Position fields in IV
    iv[4] = (ssrc >> 24) & 0xFF;
    iv[5] = (ssrc >> 16) & 0xFF;
    iv[6] = (ssrc >> 8) & 0xFF;
    iv[7] = ssrc & 0xFF;
    
    iv[8] = (roc >> 24) & 0xFF;
    iv[9] = (roc >> 16) & 0xFF;
    iv[10] = (roc >> 8) & 0xFF;
    iv[11] = roc & 0xFF;
    
    // XOR with salt
    for (int i = 0; i < SRTP_GCM_SALT_LEN; i++) {
        iv[i] ^= session_salt[i];
    }
}

/*
 * Set up SRTP key material for multiple participants in a conference
 */
srtp_err_status_t srtp_setup_conference(srtp_conference_ctx_t *conf_ctx, int max_participants) {
    if (!conf_ctx || max_participants <= 0) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    // Allocate participants array
    conf_ctx->participants = calloc(max_participants, sizeof(srtp_participant_t));
    if (!conf_ctx->participants) {
        return SRTP_FAIL_ALLOC;
    }
    
    conf_ctx->max_participants = max_participants;
    conf_ctx->num_participants = 0;
    
    pthread_mutex_init(&conf_ctx->mutex, NULL);
    
    return SRTP_SUCCESS;
}

/*
 * Add a participant to a conference
 */
srtp_err_status_t srtp_add_participant(srtp_conference_ctx_t *conf_ctx, 
                                     uint32_t ssrc, const uint8_t *key, const uint8_t *salt) {
    if (!conf_ctx || !key || !salt) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    pthread_mutex_lock(&conf_ctx->mutex);
    
    // Check if we have space
    if (conf_ctx->num_participants >= conf_ctx->max_participants) {
        pthread_mutex_unlock(&conf_ctx->mutex);
        return SRTP_FAIL_CONFERENCE_FULL;
    }
    
    // Check if SSRC already exists
    for (int i = 0; i < conf_ctx->num_participants; i++) {
        if (conf_ctx->participants[i].ssrc == ssrc) {
            pthread_mutex_unlock(&conf_ctx->mutex);
            return SRTP_FAIL_DUPLICATE_SSRC;
        }
    }
    
    // Add new participant
    srtp_participant_t *participant = &conf_ctx->participants[conf_ctx->num_participants];
    participant->ssrc = ssrc;
    
    // Initialize SRTP context for this participant
    srtp_err_status_t status = srtp_init(&participant->ctx, key, salt);
    
    if (status == SRTP_SUCCESS) {
        conf_ctx->num_participants++;
    }
    
    pthread_mutex_unlock(&conf_ctx->mutex);
    return status;
}

/*
 * Process an RTP packet in a conference context
 */
srtp_err_status_t srtp_process_conference_rtp(srtp_conference_ctx_t *conf_ctx,
                                           uint8_t *packet, size_t *packet_len,
                                           size_t max_len, bool sending) {
    if (!conf_ctx || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    if (*packet_len < sizeof(rtp_header_t)) {
        return SRTP_FAIL_PACKET_TOO_SMALL;
    }
    
    // Extract SSRC
    rtp_header_t *header = (rtp_header_t *)packet;
    uint32_t ssrc = ntohl(header->ssrc);
    
    pthread_mutex_lock(&conf_ctx->mutex);
    
    // Find matching participant
    srtp_participant_t *participant = NULL;
    for (int i = 0; i < conf_ctx->num_participants; i++) {
        if (conf_ctx->participants[i].ssrc == ssrc) {
            participant = &conf_ctx->participants[i];
            break;
        }
    }
    
    if (!participant) {
        pthread_mutex_unlock(&conf_ctx->mutex);
        return SRTP_FAIL_UNKNOWN_SSRC;
    }
    
    // Process packet with appropriate context
    srtp_err_status_t status;
    if (sending) {
        status = srtp_protect(&participant->ctx, packet, packet_len, max_len);
    } else {
        status = srtp_unprotect(&participant->ctx, packet, packet_len);
    }
    
    pthread_mutex_unlock(&conf_ctx->mutex);
    return status;
}

/*
 * Release all resources in a conference context
 */
void srtp_cleanup_conference(srtp_conference_ctx_t *conf_ctx) {
    if (!conf_ctx) {
        return;
    }
    
    pthread_mutex_lock(&conf_ctx->mutex);
    
    if (conf_ctx->participants) {
        // Free any dynamic resources in participant contexts
        free(conf_ctx->participants);
        conf_ctx->participants = NULL;
    }
    
    conf_ctx->num_participants = 0;
    
    pthread_mutex_unlock(&conf_ctx->mutex);
    pthread_mutex_destroy(&conf_ctx->mutex);
}

/*
 * Create a jitter buffer with configurable parameters
 */
srtp_err_status_t srtp_create_jitter_buffer(srtp_jitter_buffer_t *jb,
                                         uint16_t capacity,
                                         uint16_t playout_delay_ms) {
    if (!jb || capacity == 0) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    jb->buffer = calloc(capacity, sizeof(jitter_packet_t));
    if (!jb->buffer) {
        return SRTP_FAIL_ALLOC;
    }
    
    jb->capacity = capacity;
    jb->head = 0;
    jb->tail = 0;
    jb->size = 0;
    jb->playout_delay_ms = playout_delay_ms;
    jb->last_timestamp = 0;
    jb->clock_rate = 90000; // Default for video
    
    pthread_mutex_init(&jb->mutex, NULL);
    pthread_cond_init(&jb->cond, NULL);
    
    return SRTP_SUCCESS;
}

/*
 * Add a packet to the jitter buffer
 */
srtp_err_status_t srtp_jitter_buffer_add(srtp_jitter_buffer_t *jb,
                                      const uint8_t *packet, size_t packet_len,
                                      uint32_t timestamp, uint16_t seq) {
    if (!jb || !packet || packet_len == 0) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    pthread_mutex_lock(&jb->mutex);
    
    // Check if buffer is full
    if (jb->size >= jb->capacity) {
        pthread_mutex_unlock(&jb->mutex);
        return SRTP_FAIL_JITTER_BUFFER_FULL;
    }
    
    // Allocate memory for the packet
    jitter_packet_t *jp = &jb->buffer[jb->tail];
    jp->data = malloc(packet_len);
    if (!jp->data) {
        pthread_mutex_unlock(&jb->mutex);
        return SRTP_FAIL_ALLOC;
    }
    
    // Copy packet data
    memcpy(jp->data, packet, packet_len);
    jp->len = packet_len;
    jp->timestamp = timestamp;
    jp->seq = seq;
    jp->arrival_time = get_time_ms();
    
    // Update buffer state
    jb->tail = (jb->tail + 1) % jb->capacity;
    jb->size++;
    
    // Signal that data is available
    pthread_cond_signal(&jb->cond);
    
    pthread_mutex_unlock(&jb->mutex);
    return SRTP_SUCCESS;
}

/*
 * Get current time in milliseconds
 */
static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000ULL);
}

/*
 * Get next packet from jitter buffer (when it's time to play it)
 */
srtp_err_status_t srtp_jitter_buffer_get(srtp_jitter_buffer_t *jb,
                                      uint8_t *packet, size_t *packet_len,
                                      uint32_t *timestamp, uint16_t *seq,
                                      bool blocking) {
    if (!jb || !packet || !packet_len) {
        return SRTP_FAIL_NULL_ARG;
    }
    
    pthread_mutex_lock(&jb->mutex);
    
    // Wait for data if in blocking mode
    if (blocking && jb->size == 0) {
        pthread_cond_wait(&jb->cond, &jb->mutex);
    }
    
    // Check if buffer is empty
    if (jb->size == 0) {
        pthread_mutex_unlock(&jb->mutex);
        return SRTP_FAIL_JITTER_BUFFER_EMPTY;
    }
    
    // Get the oldest packet
    jitter_packet_t *jp = &jb->buffer[jb->head];
    
    // Check if it's time to play this packet
    uint64_t now = get_time_ms();
    uint64_t playout_time = jp->arrival_time + jb->playout_delay_ms;
    
    if (blocking && now < playout_time) {
        // Convert remaining time to timespec
        struct timespec ts;
        uint64_t delay_us = (playout_time - now) * 1000;
        ts.tv_sec = delay_us / 1000000;
        ts.tv_nsec = (delay_us % 1000000) * 1000;
        
        // Wait until it's time to play
        pthread_cond_timedwait(&jb->cond, &jb->mutex, &ts);
    }
    
    // If packet buffer is too small
    if (*packet_len < jp->len) {
        pthread_mutex_unlock(&jb->mutex);
        return SRTP_FAIL_BUFFER_TOO_SMALL;
    }
    
    // Copy packet data
    memcpy(packet, jp->data, jp->len);
    *packet_len = jp->len;
    
    // Copy metadata if pointers are provided
    if (timestamp) *timestamp = jp->timestamp;
    if (seq) *seq = jp->seq;
    
    // Free packet memory
    free(jp->data);
    jp->data = NULL;
    
    // Update buffer state
    jb->head = (jb->head + 1) % jb->capacity;
    jb->size--;
    
    pthread_mutex_unlock(&jb->mutex);
    return SRTP_SUCCESS;
}

/*
 * Free resources used by the jitter buffer
 */
void srtp_destroy_jitter_buffer(srtp_jitter_buffer_t *jb) {
    if (!jb) {
        return;
    }
    
    pthread_mutex_lock(&jb->mutex);
    
    // Free all packet data
    for (int i = 0; i < jb->capacity; i++) {
        if (jb->buffer[i].data) {
            free(jb->buffer[i].data);
            jb->buffer[i].data = NULL;
        }
    }
    
    // Free buffer
    free(jb->buffer);
    jb->buffer = NULL;
    
    pthread_mutex_unlock(&jb->mutex);
    
    // Destroy synchronization primitives
    pthread_mutex_destroy(&jb->mutex);
    pthread_cond_destroy(&jb->cond);
}

/*
 * Initialize the SRTP library
 */
srtp_err_status_t srtp_init_library(void) {
    // Initialize OpenSSL if needed
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    return SRTP_SUCCESS;
}

/*
 * Clean up SRTP library resources
 */
void srtp_shutdown_library(void) {
    // Clean up OpenSSL resources
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}