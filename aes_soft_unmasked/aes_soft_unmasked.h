#ifndef __AES_SOFT_UNMASKED_H__
#define __AES_SOFT_UNMASKED_H__
#include "autoconf.h"

#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
#include "libc/types.h"

typedef struct
{
	unsigned int nr;            /* Number of rounds  */
	unsigned char rk[240];      /* AES round keys    */
}
aes_soft_unmasked_context;

enum {
	AES_SOFT_UNMASKED_ENC = 0,
	AES_SOFT_UNMASKED_DEC = 1		
};

int aes_soft_unmasked_setkey_enc(aes_soft_unmasked_context *ctx, const unsigned char *key, unsigned int keybits);

int aes_soft_unmasked_setkey_dec(aes_soft_unmasked_context *ctx, const unsigned char *key, unsigned int keybits);

int aes_soft_unmasked_enc(aes_soft_unmasked_context *ctx, const unsigned char data_in[16], unsigned char data_out[16]);

int aes_soft_unmasked_dec(aes_soft_unmasked_context *ctx, const unsigned char data_in[16], unsigned char data_out[16]);

#endif /* CONFIG_USR_LIB_AES_ALGO_UNMASKED */
#endif /* __AES_SOFT_UNMASKED_H__ */
