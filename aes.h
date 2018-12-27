#ifndef __AES_H__
#define __AES_H__

#include "autoconf.h"


/* Very basic AES (unmasked, table based) stolen from mbedtls */
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
#include "aes_mbedtls/aes_soft_unmasked.h"
#endif

#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
#include "aes_anssi/aes_masked/aes_masked.h"
#endif

//#include "product.h"
/* Check if we have a hardware AES */
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
/* If we have a hardware AES, include the proper header */
#include "libcryp.h"
#endif


#define AES_BLOCK_SIZE	16
/* The AES type:
 *	- Pure software unprotected AES (from mbedtls).
 *	- Pure software masked AES (assembly from ANSSI).
 *	- Hardware AES without DMA support.
 *	- Hardware AES with DMA support.
 */
enum aes_type {
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
    AES_SOFT_MBEDTLS = 0,
#endif
#if defined(__arm__)
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    AES_SOFT_ANSSI_MASKED = 2,
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
#ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
    AES_HARD_NODMA = 3,
#endif
#ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
    AES_HARD_DMA = 4
#endif
#endif
#endif
};

enum aes_key_len {
    AES128 = 0,
    AES192 = 1,
    AES256 = 2
};

enum aes_mode {
    ECB = 0,
    CBC = 1,
    CTR = 2
};

enum aes_dir {
    AES_ENCRYPT = 0,
    AES_DECRYPT = 1
};

typedef struct {
    /* AES internal context (depends on the underlying representation) */
    union {
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
        /* mbedtls specific context */
        mbedtls_aes_context mbedtls_context;
#endif
#if defined(__arm__)
        /* ANSSI assembly contexts, mainly holding our random data and key */
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_UNMASKED
        anssi_aes_unmasked_context anssi_unmasked_context;
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
        anssi_aes_masked_context anssi_masked_context;
#endif
#ifdef  CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
        /* CRYP hardware context */
        void *hard_context;
#endif
#endif
    };
    /* For streaming modes */
    unsigned int last_off;
    uint8_t last_block_stream[AES_BLOCK_SIZE];
    /* IV */
    unsigned char iv[AES_BLOCK_SIZE];
    enum aes_type type;
    enum aes_key_len key_len;
    enum aes_mode mode;
    enum aes_dir dir;
    /* DMA related (should be NULL for software implementation) */
    void (*dma_in_complete) (void);
    void (*dma_out_complete) (void);
} aes_context;

int aes_init(aes_context * aes_ctx, const unsigned char *key,
             enum aes_key_len key_len, const unsigned char *iv,
             enum aes_mode mode, enum aes_dir dir, enum aes_type type,
             void (*dma_in_complete) (void), void (*dma_out_complete) (void),
             int dma_in_desc, int dma_out_desc);
int aes(aes_context * aes_ctx, const unsigned char *data_in,
        unsigned char *data_out, unsigned int data_len,
        int dma_in_desc, int dma_out_desc);
#ifdef CONFIG_USR_LIB_AES_SELFTESTS
int do_aes_test_vectors(int dma_in_desc, int dma_out_desc);
#endif
#ifdef CONFIG_USR_LIB_AES_PERF
int do_aes_test_performance(int dma_in_desc, int dma_out_desc);
#endif
#ifdef AES_TEST_PERFORMANCE_STLIB
int do_aes_test_performance_STLIB(void);
#endif
#endif                          /* __AES_H__ */
