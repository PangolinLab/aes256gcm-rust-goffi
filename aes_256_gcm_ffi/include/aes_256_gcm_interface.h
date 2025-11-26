#ifndef AES_256_GCM_INTERFACE_H
#define AES_256_GCM_INTERFACE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants for validation
#define AES_256_KEY_HEX_LENGTH 64      // 32 bytes -> 64 hex chars
#define GCM_NONCE_HEX_LENGTH 24        // 12 bytes -> 24 hex chars
#define AES_256_KEY_BYTES_LENGTH 32    // 32 bytes
#define GCM_NONCE_BYTES_LENGTH 12      // 12 bytes

/// AES-256-GCM Encryption
/// Parameters:
/// - key_hex: 64-character 32-byte key (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - nonce_hex: 24-character 12-byte nonce (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - plaintext_hex: Plaintext of arbitrary length (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// Returns:
/// - Success: Returns hex-encoded ciphertext+tag (must be freed with [aes_256_gcm_free] after use)
/// - Failure: Returns NULL (invalid input, key/nonce length, or encryption failure)
/// Safety:
/// - Inputs must be valid UTF-8 and null-terminated C strings.
/// - Caller must free returned pointer with [aes_256_gcm_free] to avoid memory leaks.
char* aes_256_gcm_encrypt(const char* key_hex, const char* nonce_hex, const char* plaintext_hex);

/// AES-256-GCM Decryption
/// Parameters:
/// - key_hex: 64-character 32-byte key (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - nonce_hex: 24-character 12-byte nonce (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - ciphertext_hex: Ciphertext+tag of arbitrary length (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// Returns:
/// - Success: Returns hex-encoded plaintext (must be freed with [aes_256_gcm_free] after use)
/// - Failure: Returns NULL (invalid input, key/nonce length, or decryption failure)
/// Safety:
/// - Inputs must be valid UTF-8 and null-terminated C strings.
/// - Caller must free returned pointer with [aes_256_gcm_free] to avoid memory leaks.
char* aes_256_gcm_decrypt(const char* key_hex, const char* nonce_hex, const char* ciphertext_hex);

/// Release the string returned by [aes_256_gcm_encrypt] or [aes_256_gcm_decrypt]
/// Parameter: ptr is the pointer to the result returned by encryption or decryption
/// Safety:
/// - Safe to call with NULL pointer.
/// - Do not free the same pointer twice.
void aes_256_gcm_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // AES_256_GCM_INTERFACE_H
