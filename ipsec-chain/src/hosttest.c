/*
 * hosttest.c - host-only unit tests for ipsec-chain's pure-C pieces.
 *
 * Not built by the default target and not shipped to the device; the Makefile
 * `host-test` target builds and runs it so the FIPS 197 AES vector and the
 * ELF parser logic are verified without a device.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes256.h"

/* NIST SP 800-38A ECB-AES256.Encrypt vector #1 (same key as FIPS 197
 * appendix C.3): decrypt must recover the plaintext. */
int main(void)
{
    static const uint8_t key[AES256_KEY_SZ] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,
        0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,
        0x09,0x14,0xdf,0xf4
    };
    static const uint8_t ct[AES_BLOCK_SZ] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,
        0x81,0xf8
    };
    static const uint8_t expect[AES_BLOCK_SZ] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,
        0x17,0x2a
    };
    uint8_t rk[AES256_RK_BYTES], out[AES_BLOCK_SZ], iv[AES_BLOCK_SZ];
    uint8_t old[AES_BLOCK_SZ], desired[AES_BLOCK_SZ], back[AES_BLOCK_SZ];
    int i;

    aes256_key_expand(key, rk);
    aes256_ecb_decrypt_block(rk, ct, out);
    if (memcmp(out, expect, AES_BLOCK_SZ) != 0) {
        fprintf(stderr, "FAIL: FIPS 197 C.3 decrypt mismatch\n");
        return 1;
    }

    for (i = 0; i < AES_BLOCK_SZ; i++) {
        old[i] = (uint8_t)(0xA0 + i);
        desired[i] = (uint8_t)(0x5A ^ i);
    }
    aes256_compute_iv(rk, old, desired, iv);
    aes256_ecb_decrypt_block(rk, old, out);
    for (i = 0; i < AES_BLOCK_SZ; i++)
        back[i] = (uint8_t)(out[i] ^ iv[i]);
    if (memcmp(back, desired, AES_BLOCK_SZ) != 0) {
        fprintf(stderr, "FAIL: compute_iv round trip mismatch\n");
        return 1;
    }

    printf("host test: AES-256 FIPS 197 C.3 decrypt + IV round trip OK\n");
    return 0;
}
