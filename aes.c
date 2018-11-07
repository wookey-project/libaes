/* Top header for AES */
#include "aes.h"
#include "api/types.h"
#include "api/print.h"
#include "api/syscall.h"
#include "api/random.h"
#include "librng.h"

#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
static enum crypto_key_len match_crypto_key_len(enum aes_key_len key_len)
{
    switch (key_len) {
    case AES128:
        return KEY_128;
    case AES192:
        return KEY_192;
    case AES256:
        return KEY_256;
    }

    return KEY_128;
}

static enum crypto_algo match_crypto_mode(enum aes_mode mode)
{
    switch (mode) {
    case ECB:
        return AES_ECB;
    case CBC:
        return AES_CBC;
    case CTR:
        return AES_CTR;
    }

    return AES_ECB;
}

static enum crypto_dir match_crypto_dir(enum aes_dir dir)
{
    switch (dir) {
    case AES_ENCRYPT:
        return ENCRYPT;
    case AES_DECRYPT:
        return DECRYPT;
    }

    return ENCRYPT;
}
#endif

static unsigned int get_bit_len(enum aes_key_len key_len)
{
    switch (key_len) {
    case AES128:
        return 128;
    case AES192:
        return 192;
    case AES256:
        return 256;
    }

    return 128;
}

/* This is the main AES core dispatcher, useful for software versions and useful for handling modes */
static int aes_core(aes_context * aes,
                    const unsigned char data_in[AES_BLOCK_SIZE],
                    unsigned char data_out[AES_BLOCK_SIZE], enum aes_dir dir __attribute__((unused)))
{
    switch (aes->type) {

#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
    case AES_SOFT_MBEDTLS:{
            int gnutls_dir;
            if (dir == AES_ENCRYPT) {
                gnutls_dir = MBEDTLS_AES_ENCRYPT;
            } else if (dir == AES_DECRYPT) {
                gnutls_dir = MBEDTLS_AES_DECRYPT;
            } else {
                goto err;
            }
            if (mbedtls_aes_crypt_ecb
                (&(aes->mbedtls_context), gnutls_dir, data_in, data_out)) {
                goto err;
            }
        }
        break;
#endif
#if defined(__arm__)
        /* ANSSI AES are only for the ARM architecture (they are in assemby) */
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_UNMASKED
    case AES_SOFT_ANSSI_UNMASKED:
        anssi_aes_unmasked(data_in, aes->anssi_unmasked_context.key, data_out);
        break;
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    case AES_SOFT_ANSSI_MASKED:
        anssi_aes_masked(data_in, aes->anssi_masked_context.key,
                         aes->anssi_masked_context.masks, data_out);
        break;
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
        /* AES hardware case is treated elesewhere ... */
#ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
    case AES_HARD_NODMA:
#endif
#ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
    case AES_HARD_DMA:
#endif
        goto err;
#endif
#endif
    default:
        /* in case no pure software aes is supported, avoid unused */
        data_in = data_in;
        data_out = data_out;
        goto err;
    }

    return 0;
 err:
    return -1;
}

/** AES modes **/
static void increment_iv(aes_context * aes)
{
    int j;
    /* Increment counter */
    for (j = AES_BLOCK_SIZE; j > 0; j--) {
        if (++aes->iv[j - 1] != 0) {
            break;
        }
    }

}

static void add_iv(aes_context * aes, unsigned int to_add)
{
    unsigned int i;
    for (i = 0; i < to_add; i++) {
        increment_iv(aes);
    }
}

static int aes_mode(aes_context * aes, const unsigned char *data_in,
                    unsigned char *data_out, unsigned int data_len)
{

    switch (aes->mode) {
    case ECB:{
            unsigned int i;
            if (data_len % AES_BLOCK_SIZE != 0) {
                goto err;
            }
            for (i = 0; i < data_len / AES_BLOCK_SIZE; i++) {
                if (aes_core
                    (aes, data_in + (AES_BLOCK_SIZE * i),
                     data_out + (AES_BLOCK_SIZE * i), aes->dir)) {
                    goto err;
                }
            }
            break;
        }
    case CBC:{
            if (data_len % AES_BLOCK_SIZE != 0) {
                goto err;
            }
            if (aes->dir == AES_ENCRYPT) {
                unsigned int i, j;
                uint8_t iv_tmp[AES_BLOCK_SIZE];
                uint8_t tmp[AES_BLOCK_SIZE];
                memcpy(iv_tmp, aes->iv, sizeof(iv_tmp));
                for (i = 0; i < data_len / AES_BLOCK_SIZE; i++) {
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
                        tmp[j] = data_in[(AES_BLOCK_SIZE * i) + j] ^ iv_tmp[j];
                    }
                    if (aes_core
                        (aes, tmp, data_out + (AES_BLOCK_SIZE * i), aes->dir)) {
                        goto err;
                    }
                    memcpy(iv_tmp, data_out + (AES_BLOCK_SIZE * i),
                           sizeof(iv_tmp));
                }
            } else if (aes->dir == AES_DECRYPT) {
                unsigned int i, j;
                uint8_t iv_tmp[AES_BLOCK_SIZE];
                uint8_t tmp[AES_BLOCK_SIZE];
                memcpy(iv_tmp, aes->iv, sizeof(iv_tmp));
                for (i = 0; i < data_len / AES_BLOCK_SIZE; i++) {
                    memcpy(tmp, data_in + (AES_BLOCK_SIZE * i), sizeof(tmp));
                    if (aes_core
                        (aes, data_in + (AES_BLOCK_SIZE * i),
                         data_out + (AES_BLOCK_SIZE * i), aes->dir)) {
                        goto err;
                    }
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
                        data_out[(AES_BLOCK_SIZE * i) + j] ^= iv_tmp[j];
                    }
                    memcpy(iv_tmp, tmp, sizeof(iv_tmp));
                }
            } else {
                goto err;
            }
            break;
        }
    case CTR:{
            unsigned int i;
            int offset;
            offset = aes->last_off;
            for (i = 0; i < data_len; i++) {
                if (offset == 0) {
                    if (aes_core
                        (aes, aes->iv, aes->last_block_stream, AES_ENCRYPT)) {
                        goto err;
                    }
                    increment_iv(aes);
                }
                data_out[i] = data_in[i] ^ aes->last_block_stream[offset];
                offset = (offset + 1) % AES_BLOCK_SIZE;
            }
            aes->last_off = offset;
            break;
        }
    default:
        goto err;
    }

    return 0;
 err:
    return -1;
}

int aes_init(aes_context * aes, const unsigned char *key,
             enum aes_key_len key_len, const unsigned char *iv,
             enum aes_mode mode, enum aes_dir dir, enum aes_type type,
             void (*dma_in_complete) (void), void (*dma_out_complete) (void),
             int dma_in_desc, int dma_out_desc)
{
    if (aes == NULL) {
        goto err;
    }
    aes->type = type;
    aes->key_len = key_len;
    aes->mode = mode;
    aes->dir = dir;
    aes->last_off = 0;
    memset(aes->last_block_stream, 0, sizeof(aes->last_block_stream));

    if (iv != NULL) {
        memcpy(aes->iv, iv, AES_BLOCK_SIZE);
    } else {
        memset(aes->iv, 0, AES_BLOCK_SIZE);
    }
    switch (aes->type) {
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
      case AES_SOFT_MBEDTLS: {
        switch (aes->mode) {
        case ECB:
        case CBC:
            /* Use the software unprotected mbedtls AES */
            if (dir == AES_ENCRYPT) {
                if (mbedtls_aes_setkey_enc
                    (&(aes->mbedtls_context), key, get_bit_len(aes->key_len))) {
                    goto err;
                }
            } else if (dir == AES_DECRYPT) {
                if (mbedtls_aes_setkey_dec
                    (&(aes->mbedtls_context), key, get_bit_len(aes->key_len))) {
                    goto err;
                }
            } else {
                goto err;
            }
            break;
            /* Stream mode only use encryption key schedule */
        case CTR:
            if (mbedtls_aes_setkey_enc
                (&(aes->mbedtls_context), key, get_bit_len(aes->key_len))) {
                goto err;
            }
            break;
        default:
            goto err;
        }
      break;
      }
#endif
#if defined(__arm__)
# if CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
    /* Hardware AES */
#  if CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
        case AES_HARD_NODMA: {
        aes->hard_context = NULL;
            //FIXME [PTh]: Old: crypto_init(key, match_crypto_key_len(key_len), iv, match_crypto_mode(mode), match_crypto_dir(dir));
            cryp_init(key, match_crypto_key_len(key_len), iv, 16,
                      match_crypto_mode(mode), match_crypto_dir(dir));
            break;
        }
#  endif
#  if CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
        case AES_HARD_DMA: {
        aes->hard_context = NULL;
            if ((dma_in_complete == NULL) || (dma_out_complete == NULL)) {
                printf("dma in complete or out complete is NULL\n");
                goto err;
            }
            //FIXME [PTh]: Old:crypto_init(key, match_crypto_key_len(key_len), iv, match_crypto_mode(mode), match_crypto_dir(dir));
            cryp_init(key, match_crypto_key_len(key_len), iv, 16,
                      match_crypto_mode(mode), match_crypto_dir(dir));
            aes->dma_in_complete = dma_in_complete;
            aes->dma_out_complete = dma_out_complete;
            cryp_init_dma(dma_in_complete, dma_out_complete, dma_in_desc, dma_out_desc);
      break;
      }
#  endif
# endif
# if CONFIG_USR_LIB_AES_ALGO_ANSSI_UNMASKED
    case AES_SOFT_ANSSI_UNMASKED: {
        /* Only the encryption is implemented for now ... Except for CTR mode where encryption and decryption are equivalent */
       if((aes->dir == AES_DECRYPT) && (aes->mode != CTR)){
            goto err;
        }
        memcpy(aes->anssi_unmasked_context.key, key,
               get_bit_len(aes->key_len) / 8);
        break;
    }
# endif
# if CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    case AES_SOFT_ANSSI_MASKED: {
        /* Only the encryption is implemented for now ... Except for CTR mode where encryption and decryption are equivalent */
        if((aes->dir == AES_DECRYPT) && (aes->mode != CTR)){
            goto err;
        }
        memcpy(aes->anssi_masked_context.key, key,
               get_bit_len(aes->key_len) / 8);
        /* Generate random values for the masks */
        get_random(aes->anssi_masked_context.masks, sizeof(aes->anssi_masked_context.masks));
        break;
     }
# endif
#endif /*__arm__*/
    default:
        goto err;
    }

    return 0;
 err:
    return -1;
}

// FIXME - change function name
int aes(aes_context * aes, const unsigned char *data_in,
        unsigned char *data_out, unsigned int data_len,
        int dma_in_desc, int dma_out_desc)
{
    if (aes == NULL) {
        goto err;
    }
    /* Hardware AES */
    switch (aes->type) {
#if defined(__arm__)
# ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
    case AES_HARD_NODMA:
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
    case AES_HARD_DMA:
#  endif
        if (aes->mode == CTR) {
            unsigned int i, bytes, hardware_bytes_to_encrypt;
            uint8_t last_block[AES_BLOCK_SIZE];
            /* CTR mode supports unaligned plaintext, but the hardware does not support this ... 
             */
            bytes = 0;
            if (aes->last_off != 0) {
                for (i = aes->last_off; i < AES_BLOCK_SIZE; i++) {
                    data_out[i] = data_in[i] ^ aes->last_block_stream[i];
                    bytes++;
                    aes->last_off++;
                    if (bytes > data_len) {
                        goto ctr_finished;
                    }
                }
            }
            if ((data_len - bytes) < AES_BLOCK_SIZE) {
                hardware_bytes_to_encrypt = 0;
                goto ctr_last_block;
            }
            if ((data_len - bytes) % AES_BLOCK_SIZE != 0) {
                hardware_bytes_to_encrypt =
                    (data_len - bytes) - ((data_len - bytes) % AES_BLOCK_SIZE);
            } else {
                hardware_bytes_to_encrypt = data_len - bytes;
            }
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes->type == AES_HARD_NODMA) {
                cryp_do_no_dma((data_in + bytes), (data_out + bytes),
                               hardware_bytes_to_encrypt);
                /* Increment our IV by as many blocks as needed */
                add_iv(aes, hardware_bytes_to_encrypt / AES_BLOCK_SIZE);
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes->type == AES_HARD_DMA) {
                //FIXME: encrypt_dma(data_in + bytes, data_out + bytes, hardware_bytes_to_encrypt, aes->dma_in_complete, aes->dma_out_complete);
                                /* Increment our IV by as many blocks as needed */
                // old cryp_do_dma (without fastcall)

                cryp_do_dma(data_in + bytes, data_out + bytes,
                            hardware_bytes_to_encrypt, dma_in_desc, dma_out_desc);
                add_iv(aes, hardware_bytes_to_encrypt / AES_BLOCK_SIZE);
            }
#  endif
            if (data_len - bytes - hardware_bytes_to_encrypt == 0) {
                aes->last_off = 0;
                goto ctr_finished;
            }
 ctr_last_block:
            /* Encrypt our last block with alignment */
            memset(last_block, 0, AES_BLOCK_SIZE);
            memcpy(last_block, data_in + bytes + hardware_bytes_to_encrypt,
                   data_len - bytes - hardware_bytes_to_encrypt);
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes->type == AES_HARD_NODMA) {
                //FIXME: encrypt_no_dma(last_block, aes->last_block_stream, AES_BLOCK_SIZE);
                /* Increment our IV by one block */
                cryp_do_no_dma((data_in + bytes), (data_out + bytes),
                               hardware_bytes_to_encrypt);
                add_iv(aes, 1);
            } else {
                goto err;
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes->type == AES_HARD_DMA) {
                //FIXME: encrypt_dma(last_block, aes->last_block_stream, AES_BLOCK_SIZE, aes->dma_in_complete, aes->dma_out_complete);
                cryp_do_dma(data_in + bytes, data_out + bytes,
                            hardware_bytes_to_encrypt, dma_in_desc, dma_out_desc);
                /* Increment our IV by as many blocks as needed */
                /* Increment our IV by one block */
                add_iv(aes, 1);
            } else {
                goto err;
            }
#  endif
            for (i = 0; i < (data_len - bytes - hardware_bytes_to_encrypt); i++) {
                data_out[bytes + hardware_bytes_to_encrypt + i] =
                    aes->last_block_stream[i];
                aes->last_off++;
            }
            /* Get back our last block key stream */
            for (i = 0; i < AES_BLOCK_SIZE; i++) {
                aes->last_block_stream[i] ^= last_block[i];
            }
 ctr_finished:
            break;
        } else {
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes->type == AES_HARD_NODMA) {
                //FIXME: encrypt_no_dma(data_in, data_out, data_len);
                cryp_do_no_dma(data_in, data_out, data_len);
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes->type == AES_HARD_DMA) {
                //FIXME: encrypt_dma(data_in, data_out, data_len, aes->dma_in_complete, aes->dma_out_complete);
                cryp_do_dma(data_in, data_out, data_len, dma_in_desc, dma_out_desc);
            }
#  endif
             else {
                goto err;
            }
        }
        break;
# endif
# ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_UNMASKED
    case AES_SOFT_ANSSI_UNMASKED:
        /* Use the software unmasked AES */
        if (aes_mode(aes, data_in, data_out, data_len)) {
            goto err;
        }
        break;

# endif
# ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
   case AES_SOFT_ANSSI_MASKED:
         /* Use the software unmasked AES */
        if (aes_mode(aes, data_in, data_out, data_len)) {
            goto err;
        }
        break;
# endif
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
    case AES_SOFT_MBEDTLS:
        /* Use the software unmasked AES */
        if (aes_mode(aes, data_in, data_out, data_len)) {
            goto err;
        }
        break;
#endif
    default:
        /* Unknown AES ... */
        goto err;
    }

    return 0;
 err:
    return -1;
}
