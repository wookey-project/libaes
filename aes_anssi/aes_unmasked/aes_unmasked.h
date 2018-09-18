#ifndef __AES_UNMASKED_H__
#define __AES_UNMASKED_H__

/* Key and random masks */
typedef struct {
	unsigned char key[32];
} anssi_aes_unmasked_context;

void anssi_aes_unmasked(const unsigned char *, const unsigned char *, unsigned char *);

#endif
