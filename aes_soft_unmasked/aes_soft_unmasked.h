#ifndef __AES_SOFT_UNMASKED_H__
#define __AES_SOFT_UNMASKED_H__
#include "autoconf_aes_glue.h"

#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
#include "libc/types.h"

typedef struct
{
	uint32_t nr;            /* Number of rounds  */
#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE
	uint8_t rk[240];      /* AES round keys    */
#endif
#ifdef  CONFIG_USR_LIB_AES_ALGO_UNMASKED_TABLE
	uint32_t rk[64]; /* AES round keys  */
#endif
}
aes_soft_unmasked_context;

enum {
	AES_SOFT_UNMASKED_ENC = 0,
	AES_SOFT_UNMASKED_DEC = 1		
};

int aes_soft_unmasked_setkey_enc(aes_soft_unmasked_context *ctx, const uint8_t *key, uint32_t keybits);

int aes_soft_unmasked_setkey_dec(aes_soft_unmasked_context *ctx, const uint8_t *key, uint32_t keybits);

int aes_soft_unmasked_enc(aes_soft_unmasked_context *ctx, const uint8_t data_in[16], uint8_t data_out[16]);

int aes_soft_unmasked_dec(aes_soft_unmasked_context *ctx, const uint8_t data_in[16], uint8_t data_out[16]);

#endif /* CONFIG_USR_LIB_AES_ALGO_UNMASKED */
#endif /* __AES_SOFT_UNMASKED_H__ */
