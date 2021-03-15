/* Top header for AES */
#include "api/aes.h"
#include "libc/types.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/syscall.h"
#include "libc/random.h"


/* AES CTR XOR masking compilation optional support 
 * NOTE: CTR mode XOR with counters is shuffled and masked.
 */
#define USE_AES_CTR_MASKING 1
/* AES CBC XOR masking compilation optional support
 * NOTE: CBC mode XOR with IV is shuffled and masked.
 */
#define USE_AES_CBC_MASKING 1

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
    default:
        return KEY_128;
    }
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
    default:
        return AES_ECB;
    }
}

static enum crypto_dir match_crypto_dir(enum aes_dir dir)
{
    switch (dir) {
    case AES_ENCRYPT:
        return ENCRYPT;
    case AES_DECRYPT:
        return DECRYPT;
    default:
        return ENCRYPT;
    }
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
    default:
        return 128;
    }
}

/* This is the main AES core dispatcher, useful for software versions and useful for handling modes */
static int aes_core(aes_context * aes_ctx,
                    const unsigned char data_in[AES_BLOCK_SIZE] __attribute__((unused)),
                    unsigned char data_out[AES_BLOCK_SIZE] __attribute__((unused)),
                    enum aes_dir dir __attribute__((unused)))
{
    switch (aes_ctx->type) {

#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
    case AES_SOFT_UNMASKED:{
            if (dir == AES_ENCRYPT) {
	        if (aes_soft_unmasked_enc
        	        (&(aes_ctx->soft_unmasked_context), data_in, data_out)) {
                	goto err;
            	}
            } else if (dir == AES_DECRYPT) {
	        if (aes_soft_unmasked_dec
        	        (&(aes_ctx->soft_unmasked_context), data_in, data_out)) {
                	goto err;
            	}
            } else {
                goto err;
            }
        }
        break;
#endif
#if defined(__arm__)
        /* ANSSI AES are only for the ARM architecture (they are in assemby) */
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    case AES_SOFT_ANSSI_MASKED:
	if(dir == AES_ENCRYPT){
		if(aes(MODE_ENC, &(aes_ctx->anssi_masked_context), NULL, data_in, data_out, NULL, NULL) != NO_ERROR){
			goto err;
		}
	}
	else if (dir == AES_DECRYPT) {
		if(aes(MODE_DEC, &(aes_ctx->anssi_masked_context), NULL, data_in, data_out, NULL, NULL) != NO_ERROR){
			goto err;
		}
	}
	else{
		goto err;
	}
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
        goto err;
    }

    return 0;
 err:
    return -1;
}

/** AES modes **/

/* NOTE: we force *NO optimization* here to ensure
 * that our masking and shuffling related protections are
 * not removed by the compiler.
 */
#ifdef __GNUC__
#ifdef __clang__
# pragma clang optimize off
#else
# pragma GCC push_options
# pragma GCC optimize("O0")
#endif
#endif
#if ((USE_AES_CTR_MASKING == 1) || (USE_AES_CBC_MASKING == 1))
/**** Generate a random permutation using Knuth Shuffle ****/
static int gen_permutation(unsigned char *perm, unsigned int size){
	unsigned int i, j;

	if(perm == NULL){
		goto err;
	}
	for(i = 0; i < size; i++){
		perm[i] = i;
	}
	if(size <= 2){
		return 0;
	}
	for(i = 0; i <= (size - 2); i++){
		unsigned char swp;
		if(get_random((unsigned char*)&j, sizeof(j)) != MBED_ERROR_NONE){
			goto err;
		}
		j = (j % (size - i)) + i;
		swp = perm[i];
		perm[i] = perm[j];
		perm[j] = swp;
	}

	return 0;
err:
	return -1;
}

/* Generate masks */
static int gen_masks(unsigned char *masks, unsigned int size){
	unsigned int i;

	if(masks == NULL){
		goto err;
	}

	for(i = 0; i < size; i++){
		if(get_random(&(masks[i]), sizeof(unsigned char)) != MBED_ERROR_NONE){
			goto err;
		}
	}
	
	return 0;
err:
	return -1;
}
#endif

/*** IV incrementation ****/
void increment_iv(uint8_t IV[16])
{
    int j;
    unsigned char end = 0, dummy = 0;

    /* Increment counter */
    for (j = AES_BLOCK_SIZE; j > 0; j--) {
	if(end == 0){
            if (++IV[j - 1] != 0) {        
                end = 1;
            }
        }
        else{
           dummy++;
        }
    }
}

void add_iv(uint8_t IV[16], unsigned int to_add)
{
    unsigned int i;
    for (i = 0; i < to_add; i++) {
        increment_iv(IV);
    }
}

void increment_iv_ctx(aes_context * aes_ctx)
{
    increment_iv(aes_ctx->iv);
}

void add_iv_ctx(aes_context * aes_ctx, unsigned int to_add)
{
    add_iv(aes_ctx->iv, to_add);
}

static int aes_mode(aes_context * aes_ctx, const unsigned char *data_in,
                    unsigned char *data_out, unsigned int data_len)
{

    switch (aes_ctx->mode) {
    case ECB:{
            unsigned int i;
            if ((data_len % AES_BLOCK_SIZE) != 0) {
                goto err;
            }
            for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
                if (aes_core
                    (aes_ctx, data_in + (AES_BLOCK_SIZE * i),
                     data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
                    goto err;
                }
            }
            break;
        }
    case CBC:{
            if ((data_len % AES_BLOCK_SIZE) != 0) {
                goto err;
            }
            if (aes_ctx->dir == AES_ENCRYPT) {
                unsigned int i, j;
                uint8_t iv_tmp[AES_BLOCK_SIZE];
                uint8_t tmp[AES_BLOCK_SIZE];
                memcpy(iv_tmp, aes_ctx->iv, sizeof(iv_tmp));
                for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
#if (USE_AES_CBC_MASKING == 1)
            	    /* In case of CBC masking, we generate a permutation and masks */
		    unsigned char cbc_perm[AES_BLOCK_SIZE] = { 0 };
		    unsigned char cbc_masks[AES_BLOCK_SIZE] = { 0 }; 
	            if(gen_permutation(cbc_perm, AES_BLOCK_SIZE)){
			goto err;
		    }
                    if(gen_masks(cbc_masks, AES_BLOCK_SIZE)){
			goto err;
		    }
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
                        tmp[cbc_perm[j]]  = data_in[(AES_BLOCK_SIZE * i) + cbc_perm[j]] ^ cbc_masks[cbc_perm[j]];
			tmp[cbc_perm[j]] ^= iv_tmp[cbc_perm[j]];
			tmp[cbc_perm[j]] ^= cbc_masks[cbc_perm[j]];
                    }
#else
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
                        tmp[j] = data_in[(AES_BLOCK_SIZE * i) + j] ^ iv_tmp[j];
                    }
#endif
                    if (aes_core
                        (aes_ctx, tmp, data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
                        goto err;
                    }
                    memcpy(iv_tmp, data_out + (AES_BLOCK_SIZE * i),
                           sizeof(iv_tmp));
                }
            } else if (aes_ctx->dir == AES_DECRYPT) {
                unsigned int i, j;
                uint8_t iv_tmp[AES_BLOCK_SIZE];
                uint8_t tmp[AES_BLOCK_SIZE];
                memcpy(iv_tmp, aes_ctx->iv, sizeof(iv_tmp));
                for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
                    memcpy(tmp, data_in + (AES_BLOCK_SIZE * i), sizeof(tmp));
                    if (aes_core
                        (aes_ctx, data_in + (AES_BLOCK_SIZE * i),
                         data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
                        goto err;
                    }
#if (USE_AES_CBC_MASKING == 1)
            	    /* In case of CBC masking, we generate a permutation and masks */
		    unsigned char cbc_perm[AES_BLOCK_SIZE] = { 0 };
		    unsigned char cbc_masks[AES_BLOCK_SIZE] = { 0 }; 
	            if(gen_permutation(cbc_perm, AES_BLOCK_SIZE)){
			goto err;
		    }
                    if(gen_masks(cbc_masks, AES_BLOCK_SIZE)){
			goto err;
		    }
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
			data_out[(AES_BLOCK_SIZE * i) + cbc_perm[j]] ^= cbc_masks[cbc_perm[j]];
			data_out[(AES_BLOCK_SIZE * i) + cbc_perm[j]] ^= iv_tmp[cbc_perm[j]];
			data_out[(AES_BLOCK_SIZE * i) + cbc_perm[j]] ^= cbc_masks[cbc_perm[j]];
                    }
#else
                    for (j = 0; j < AES_BLOCK_SIZE; j++) {
                        data_out[(AES_BLOCK_SIZE * i) + j] ^= iv_tmp[j];
                    }
#endif
                    memcpy(iv_tmp, tmp, sizeof(iv_tmp));
                }
            } else {
                goto err;
            }
            break;
        }
    case CTR:{
            unsigned int i;
            unsigned int offset;
#if (USE_AES_CTR_MASKING == 1)
    	    /* In case of AES CTR, we use additional protections against SCA
	     * through masking and shuffling when handling the IV.
	     */
	    unsigned int num_blocks = 0;
	    unsigned char ctr_perm[AES_BLOCK_SIZE] = { 0 };
	    unsigned char ctr_masks[AES_BLOCK_SIZE] = { 0 };
#endif
   	    /* Sanity check on the offset */
	    if(aes_ctx->last_off > AES_BLOCK_SIZE){
	 	goto err;
	    }
#if (USE_AES_CTR_MASKING == 1)
	    if(aes_ctx->last_off != 0){
                /* First block handling */
                if(gen_permutation(ctr_perm, AES_BLOCK_SIZE - (aes_ctx->last_off))){
			goto err;
		}
                if(gen_masks(ctr_masks, AES_BLOCK_SIZE - (aes_ctx->last_off))){
			goto err;
		}
	    }
#endif
            offset = aes_ctx->last_off;
            for (i = 0; i < data_len; i++) {
#if (USE_AES_CTR_MASKING == 1)
                unsigned int perm_size, i_perm, offset_perm;
#endif
                if (offset == 0) {
#if (USE_AES_CTR_MASKING == 1)
		    num_blocks++;
                    if(((data_len - i) < AES_BLOCK_SIZE) && ((data_len % AES_BLOCK_SIZE) != 0)){
                        /* Last block handling */
                        perm_size = (data_len - i);
                    }
                    else{
                        perm_size = AES_BLOCK_SIZE;
                    }
                    if(gen_permutation(ctr_perm, perm_size)){
			goto err;
		    }
                    if(gen_masks(ctr_masks, perm_size)){
			goto err;
		    }
#endif
                    if (aes_core
                        (aes_ctx, aes_ctx->iv, aes_ctx->last_block_stream, AES_ENCRYPT)) {
                        goto err;
                    }
                    increment_iv_ctx(aes_ctx);
                }
#if (USE_AES_CTR_MASKING == 1)
		if((aes_ctx->last_off != 0) && (i < (AES_BLOCK_SIZE - (aes_ctx->last_off)))){
			/* First block handling */
			if(offset < aes_ctx->last_off){
				/* Should not happen, but better safe than sorry */
				goto err;
			} 
                	i_perm = ctr_perm[offset - aes_ctx->last_off];
			offset_perm = i_perm + aes_ctx->last_off;
		}
		else{
                	i_perm = offset_perm = ctr_perm[offset];	
		}
		if(num_blocks >= 1){
			/* Offset by the number of treated blocks */
			i_perm += (AES_BLOCK_SIZE * (num_blocks - 1));
		}
		if((aes_ctx->last_off != 0) && (i >= (AES_BLOCK_SIZE - (aes_ctx->last_off)))){
			/* Block others than first block */
			i_perm += (AES_BLOCK_SIZE - (aes_ctx->last_off));
		}
		/* Sanity check before access */
		if((i_perm >= data_len) || (offset_perm >= AES_BLOCK_SIZE)){
			goto err;
		}
                /* Shuffled and masked IV xoring */
                data_out[i_perm]  = data_in[i_perm] ^ ctr_masks[offset_perm];
                data_out[i_perm] ^= aes_ctx->last_block_stream[offset_perm];
                data_out[i_perm] ^= ctr_masks[offset_perm];
#else
                data_out[i]  = data_in[i] ^ aes_ctx->last_block_stream[offset];
#endif
                /***/
                offset = (offset + 1) % AES_BLOCK_SIZE;
            }
            aes_ctx->last_off = offset;
            break;
        }
    default:
        goto err;
    }

    return 0;
 err:
    return -1;
}
#ifdef __GNUC__
#ifdef __clang__
# pragma clang optimize on
#else
# pragma GCC pop_options
#endif
#endif


int aes_init(aes_context * aes_ctx, const unsigned char *key,
             enum aes_key_len key_len, const unsigned char *iv,
             enum aes_mode mode, enum aes_dir dir, enum aes_type type,
             UNUSED_ATTR user_dma_handler_t dma_in_complete, UNUSED_ATTR user_dma_handler_t dma_out_complete,
             UNUSED_ATTR int dma_in_desc, UNUSED_ATTR int dma_out_desc)
{
    if (aes_ctx == NULL) {
        goto err;
    }
    aes_ctx->type = type;
    aes_ctx->key_len = key_len;
    aes_ctx->mode = mode;
    aes_ctx->dir = dir;
    aes_ctx->last_off = 0;
    memset(aes_ctx->last_block_stream, 0, sizeof(aes_ctx->last_block_stream));

    if (iv != NULL) {
        memcpy(aes_ctx->iv, iv, AES_BLOCK_SIZE);
    } else {
        memset(aes_ctx->iv, 0, AES_BLOCK_SIZE);
    }
    switch (aes_ctx->type) {
#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
      case AES_SOFT_UNMASKED: {
        switch (aes_ctx->mode) {
        case ECB:
        case CBC:
            /* Use the software unprotected mbedtls AES */
            if (dir == AES_ENCRYPT) {
                if (aes_soft_unmasked_setkey_enc
                    (&(aes_ctx->soft_unmasked_context), key, get_bit_len(aes_ctx->key_len))) {
                    goto err;
                }
            } else if (dir == AES_DECRYPT) {
                if (aes_soft_unmasked_setkey_dec
                    (&(aes_ctx->soft_unmasked_context), key, get_bit_len(aes_ctx->key_len))) {
                    goto err;
                }
            } else {
                goto err;
            }
            break;
            /* Stream mode only use encryption key schedule */
        case CTR:
            if (aes_soft_unmasked_setkey_enc
                (&(aes_ctx->soft_unmasked_context), key, get_bit_len(aes_ctx->key_len))) {
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
# ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
    /* Hardware AES */
#  ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
        case AES_HARD_NODMA: {
        aes_ctx->hard_context = NULL;
            //FIXME [PTh]: Old: crypto_init(key, match_crypto_key_len(key_len), iv, match_crypto_mode(mode), match_crypto_dir(dir));
            cryp_init(key, match_crypto_key_len(key_len), iv, 16,
                      match_crypto_mode(mode), match_crypto_dir(dir));
            break;
        }
#  endif
#  ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
        case AES_HARD_DMA: {
        aes_ctx->hard_context = NULL;
            if ((dma_in_complete == NULL) || (dma_out_complete == NULL)) {
                printf("dma in complete or out complete is NULL\n");
                goto err;
            }
            //FIXME [PTh]: Old:crypto_init(key, match_crypto_key_len(key_len), iv, match_crypto_mode(mode), match_crypto_dir(dir));
            cryp_init(key, match_crypto_key_len(key_len), iv, 16,
                      match_crypto_mode(mode), match_crypto_dir(dir));
            aes_ctx->dma_in_complete = dma_in_complete;
            aes_ctx->dma_out_complete = dma_out_complete;
            cryp_init_dma(dma_in_complete, dma_out_complete, dma_in_desc, dma_out_desc);
      break;
      }
#  endif
# endif
# ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    case AES_SOFT_ANSSI_MASKED: {
	if(dir == AES_ENCRYPT){
		if(aes(MODE_KEYINIT|MODE_AESINIT_ENC, &(aes_ctx->anssi_masked_context), key, NULL, NULL, NULL, NULL) != NO_ERROR){
			goto err;
		}
	}
	else if (dir == AES_DECRYPT){
		if(aes_ctx->mode == CTR){
			if(aes(MODE_KEYINIT|MODE_AESINIT_ENC, &(aes_ctx->anssi_masked_context), key, NULL, NULL, NULL, NULL) != NO_ERROR){
				goto err;
			}
		}
		else{
			if(aes(MODE_KEYINIT|MODE_AESINIT_DEC, &(aes_ctx->anssi_masked_context), key, NULL, NULL, NULL, NULL) != NO_ERROR){
				goto err;
			}
		}
	}
	else{
		goto err;
	}
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

int aes_exec(aes_context * aes_ctx, const unsigned char *data_in,
        unsigned char *data_out, unsigned int data_len,
        UNUSED_ATTR int dma_in_desc, UNUSED_ATTR int dma_out_desc)
{
    if (aes_ctx == NULL) {
        goto err;
    }
    /* Hardware AES */
    switch (aes_ctx->type) {
#if defined(__arm__)
# ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
    case AES_HARD_NODMA:
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
    case AES_HARD_DMA:
#  endif
        if (aes_ctx->mode == CTR) {
            unsigned int i, bytes, hardware_bytes_to_encrypt;
            uint8_t last_block[AES_BLOCK_SIZE];
            /* CTR mode supports unaligned plaintext, but the hardware does not support this ...
             */
            bytes = 0;
            if (aes_ctx->last_off != 0) {
                for (i = aes_ctx->last_off; i < AES_BLOCK_SIZE; i++) {
                    data_out[i] = data_in[i] ^ aes_ctx->last_block_stream[i];
                    bytes++;
                    aes_ctx->last_off++;
                    if (bytes > data_len) {
                        goto ctr_finished;
                    }
                }
            }
            if ((data_len - bytes) < AES_BLOCK_SIZE) {
                hardware_bytes_to_encrypt = 0;
                goto ctr_last_block;
            }
            if (((data_len - bytes) % AES_BLOCK_SIZE) != 0) {
                hardware_bytes_to_encrypt =
                    (data_len - bytes) - ((data_len - bytes) % AES_BLOCK_SIZE);
            } else {
                hardware_bytes_to_encrypt = data_len - bytes;
            }
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes_ctx->type == AES_HARD_NODMA) {
                cryp_do_no_dma((data_in + bytes), (data_out + bytes),
                               hardware_bytes_to_encrypt);
                /* Increment our IV by as many blocks as needed */
                add_iv_ctx(aes, hardware_bytes_to_encrypt / AES_BLOCK_SIZE);
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes_ctx->type == AES_HARD_DMA) {
                /* Increment our IV by as many blocks as needed */
                cryp_do_dma(data_in + bytes, data_out + bytes,
                            hardware_bytes_to_encrypt, dma_in_desc, dma_out_desc);
                add_iv_ctx(aes_ctx, hardware_bytes_to_encrypt / AES_BLOCK_SIZE);
            }
#  endif
            if ((data_len - bytes - hardware_bytes_to_encrypt) == 0) {
                aes_ctx->last_off = 0;
                goto ctr_finished;
            }
 ctr_last_block:
            /* Encrypt our last block with alignment */
            memset(last_block, 0, AES_BLOCK_SIZE);
            memcpy(last_block, data_in + bytes + hardware_bytes_to_encrypt,
                   data_len - bytes - hardware_bytes_to_encrypt);
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes_ctx->type == AES_HARD_NODMA) {
                /* Increment our IV by one block */
                cryp_do_no_dma((data_in + bytes), (data_out + bytes),
                               hardware_bytes_to_encrypt);
                add_iv_ctx(aes, 1);
            } else {
                goto err;
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes_ctx->type == AES_HARD_DMA) {
                cryp_do_dma(data_in + bytes, data_out + bytes,
                            hardware_bytes_to_encrypt, dma_in_desc, dma_out_desc);
                /* Increment our IV by as many blocks as needed */
                /* Increment our IV by one block */
                add_iv_ctx(aes_ctx, 1);
            } else {
                goto err;
            }
#  endif
            for (i = 0; i < (data_len - bytes - hardware_bytes_to_encrypt); i++) {
                data_out[bytes + hardware_bytes_to_encrypt + i] =
                    aes_ctx->last_block_stream[i];
                aes_ctx->last_off++;
            }
            /* Get back our last block key stream */
            for (i = 0; i < AES_BLOCK_SIZE; i++) {
                aes_ctx->last_block_stream[i] ^= last_block[i];
            }
 ctr_finished:
            break;
        } else {
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
            if (aes_ctx->type == AES_HARD_NODMA) {
                cryp_do_no_dma(data_in, data_out, data_len);
            }
#  endif
#  ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
            if (aes_ctx->type == AES_HARD_DMA) {
                cryp_do_dma(data_in, data_out, data_len, dma_in_desc, dma_out_desc);
            }
#  endif
             else {
                goto err;
            }
        }
        break;
# endif
# ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
   case AES_SOFT_ANSSI_MASKED:
         /* Use the software masked AES */
        if (aes_mode(aes_ctx, data_in, data_out, data_len)) {
            goto err;
        }
        break;
# endif
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
    case AES_SOFT_UNMASKED:
        /* Use the software unmasked AES */
        if (aes_mode(aes_ctx, data_in, data_out, data_len)) {
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
