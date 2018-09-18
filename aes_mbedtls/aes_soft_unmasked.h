/**
 * \file aes.h
 *
 * \brief AES block cipher
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_AES_H
#define MBEDTLS_AES_H

#include "api/types.h"

#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES

#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR

/* padlock.c and aesni.c rely on these values! */
#define MBEDTLS_AES_ENCRYPT     1
#define MBEDTLS_AES_DECRYPT     0

#define MBEDTLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES context structure
 *
 * \note           buf is able to hold 32 extra bytes, which can be used:
 *                 - for alignment purposes if VIA padlock is used, and/or
 *                 - to simplify key expansion in the 256-bit case by
 *                 generating an extra round key
 */
typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t *rk;               /*!<  AES round keys    */
    uint32_t buf[68];           /*!<  unaligned data    */
}
mbedtls_aes_context;

/**
 * \brief          Initialize AES context
 *
 * \param ctx      AES context to be initialized
 */
void mbedtls_aes_init( mbedtls_aes_context *ctx );

/**
 * \brief          Clear AES context
 *
 * \param ctx      AES context to be cleared
 */
void mbedtls_aes_free( mbedtls_aes_context *ctx );

/**
 * \brief          AES key schedule (encryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          AES key schedule (decryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      decryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          AES-ECB block encryption/decryption
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );


#endif /* aes.h */
