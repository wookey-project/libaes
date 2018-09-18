#ifndef __AES_MASKED_H__
#define __AES_MASKED_H__

/* Key and random masks */
typedef struct {
        unsigned char key[32];
        unsigned char masks[18];
} anssi_aes_masked_context;

void anssi_aes_masked(const unsigned char *, const unsigned char *, const unsigned char *, unsigned char *);

#endif
