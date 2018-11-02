#include "autoconf.h"
#include "aes.h"
#include "api/print.h"
#include "api/types.h"
#include "api/syscall.h"
//#include "api/malloc.h"


#if defined(CONFIG_USR_LIB_AES_PERF) || defined(CONFIG_USR_LIB_AES_SELFTESTS)

typedef struct {
    const char *name;
    enum aes_type type;
} aes_desc;


unsigned int i, j;

volatile uint64_t start_init, end_init, start_crypt, end_crypt;

const aes_desc available_aes[] = {
#ifdef CONFIG_USR_LIB_AES_ALGO_MBEDTLS
    {
     .name = "AES_SOFT_MBEDTLS",
     .type = AES_SOFT_MBEDTLS,
     },
#endif
#if defined(__arm__)
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_UNMASKED
    {
     .name = "AES_SOFT_ANSSI_UNMASKED",
     .type = AES_SOFT_ANSSI_UNMASKED,
     },
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
    {
     .name = "AES_SOFT_ANSSI_MASKED",
     .type = AES_SOFT_ANSSI_MASKED,
     },
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
    {
     .name = "AES_HARD_NODMA",
     .type = AES_HARD_NODMA,
     },
#endif
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
    {
     .name = "AES_HARD_DMA",
     .type = AES_HARD_DMA,
     },
#endif
#endif
#endif
};

#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
static volatile unsigned char dma_in_ok = 0;
static void dma_in_complete(uint8_t irq __attribute__ ((unused)),
                            uint32_t status __attribute__ ((unused)))
{
    if(status & DMA_DIRECT_MODE_ERROR){
        status_reg.dmain_dm_err = true;
    }
    if(status & DMA_TRANSFER_ERROR){
        status_reg.dmain_tr_err = true;
    }
#if 0
    if (get_reg_value(&status, DMA_HISR_HTIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_HTIFx_Pos(DMA2_STREAM_CRYP_IN)) && 
       !get_reg_value(&status, DMA_HISR_TCIFx_Msk(DMA2_STREAM_CRYP_IN),
                      DMA_HISR_TCIFx_Pos(DMA2_STREAM_CRYP_IN))) {
        return;
    }
#endif
    dma_in_ok = 1;
    return;
}

static uint64_t get_cycles(void)
{
  uint64_t val = 0;
  sys_get_systick(&val, PREC_CYCLE);
  return val;
}

static volatile unsigned char dma_out_ok = 0;
static void dma_out_complete(uint8_t irq __attribute__ ((unused)),
                             uint32_t status __attribute__ ((unused)))
{
    if(status & DMA_DIRECT_MODE_ERROR){
        status_reg.dmain_dm_err = true;
    }
    if(status & DMA_TRANSFER_ERROR){
        status_reg.dmain_tr_err = true;
    }

#if 0
    if (get_reg_value(&status, DMA_HISR_HTIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_HTIFx_Pos(DMA2_STREAM_CRYP_OUT)) &&
       !get_reg_value(&status, DMA_HISR_TCIFx_Msk(DMA2_STREAM_CRYP_OUT),
                      DMA_HISR_TCIFx_Pos(DMA2_STREAM_CRYP_OUT))) {
        return;
    }
#endif
    dma_out_ok = 1;
    //end_crypt = get_cycles();
        //cryp_do_dma(msg + bytes, msg + bytes,
    //            hardware_bytes_to_encrypt);
    return;
}
#endif

#endif

#ifdef CONFIG_USR_LIB_AES_SELFTESTS
/*** AES test vectors, stolen from NIST 800-38A 
 *  (http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) 
 *****/
typedef struct {
    /* Test case name */
    const char *name;
    /* AES parameters */
    enum aes_key_len key_len;
    enum aes_mode mode;
    enum aes_dir dir;
    /* Message */
    const uint8_t *msg;
    uint32_t msg_len;
    /* Key */
    const uint8_t *key;
    /* IV */
    const uint8_t *iv;
    /* Expected output and associated length */
    const uint8_t *exp_out;
    uint8_t exp_out_len;
} aes_test_case;

/*** AES ECB ****/
static const aes_test_case aes128_ecb_enc_test_case_1 = {
    .name = "AES128_ECB_ENC_1",
    .key_len = AES128,
    .mode = ECB,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv = NULL,
    .exp_out =
        (uint8_t *)
        "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes128_ecb_dec_test_case_1 = {
    .name = "AES128_ECB_DEC_1",
    .key_len = AES128,
    .mode = ECB,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv = NULL,
    .msg =
        (uint8_t *)
        "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4",
    .msg_len = 4 * 16,
};

static const aes_test_case aes192_ecb_enc_test_case_1 = {
    .name = "AES192_ECB_ENC_1",
    .key_len = AES192,
    .mode = ECB,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv = NULL,
    .exp_out =
        (uint8_t *)
        "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes192_ecb_dec_test_case_1 = {
    .name = "AES192_ECB_DEC_1",
    .key_len = AES192,
    .mode = ECB,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv = NULL,
    .msg =
        (uint8_t *)
        "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e",
    .msg_len = 4 * 16,
};

static const aes_test_case aes256_ecb_enc_test_case_1 = {
    .name = "AES256_ECB_ENC_1",
    .key_len = AES256,
    .mode = ECB,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv = NULL,
    .exp_out =
        (uint8_t *)
        "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes256_ecb_dec_test_case_1 = {
    .name = "AES256_ECB_DEC_1",
    .key_len = AES256,
    .mode = ECB,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv = NULL,
    .msg =
        (uint8_t *)
        "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7",
    .msg_len = 4 * 16,
};

/*** AES CBC ****/
static const aes_test_case aes128_cbc_enc_test_case_1 = {
    .name = "AES128_CBC_ENC_1",
    .key_len = AES128,
    .mode = CBC,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .exp_out =
        (uint8_t *)
        "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes128_cbc_dec_test_case_1 = {
    .name = "AES128_CBC_DEC_1",
    .key_len = AES128,
    .mode = CBC,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .msg =
        (uint8_t *)
        "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7",
    .msg_len = 4 * 16,
};

static const aes_test_case aes192_cbc_enc_test_case_1 = {
    .name = "AES192_CBC_ENC_1",
    .key_len = AES192,
    .mode = CBC,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .exp_out =
        (uint8_t *)
        "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes256_cbc_enc_test_case_1 = {
    .name = "AES256_CBC_ENC_1",
    .key_len = AES256,
    .mode = CBC,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .exp_out =
        (uint8_t *)
        "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes256_cbc_dec_test_case_1 = {
    .name = "AES256_CBC_DEC_1",
    .key_len = AES256,
    .mode = CBC,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .msg =
        (uint8_t *)
        "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b",
    .msg_len = 4 * 16,
};

static const aes_test_case aes192_cbc_dec_test_case_1 = {
    .name = "AES192_CBC_DEC_1",
    .key_len = AES192,
    .mode = CBC,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv =
        (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    .msg =
        (uint8_t *)
        "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd",
    .msg_len = 4 * 16,
};

/*** AES CTR ****/
static const aes_test_case aes128_ctr_enc_test_case_1 = {
    .name = "AES128_CTR_ENC_1",
    .key_len = AES128,
    .mode = CTR,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .exp_out =
        (uint8_t *)
        "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes128_ctr_dec_test_case_1 = {
    .name = "AES128_CTR_DEC_1",
    .key_len = AES128,
    .mode = CTR,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .msg =
        (uint8_t *)
        "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee",
    .msg_len = 4 * 16,
};

static const aes_test_case aes192_ctr_enc_test_case_1 = {
    .name = "AES192_CTR_ENC_1",
    .key_len = AES192,
    .mode = CTR,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .exp_out =
        (uint8_t *)
        "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes192_ctr_dec_test_case_1 = {
    .name = "AES192_CTR_DEC_1",
    .key_len = AES192,
    .mode = CTR,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .msg =
        (uint8_t *)
        "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50",
    .msg_len = 4 * 16,
};

static const aes_test_case aes256_ctr_enc_test_case_1 = {
    .name = "AES256_CTR_ENC_1",
    .key_len = AES256,
    .mode = CTR,
    .dir = AES_ENCRYPT,
    .msg =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .msg_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .exp_out =
        (uint8_t *)
        "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6",
    .exp_out_len = 4 * 16,
};

static const aes_test_case aes256_ctr_dec_test_case_1 = {
    .name = "AES256_CTR_DEC_1",
    .key_len = AES256,
    .mode = CTR,
    .dir = AES_DECRYPT,
    .exp_out =
        (uint8_t *)
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
    .exp_out_len = 4 * 16,
    .key =
        (uint8_t *)
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    .iv =
        (uint8_t *)
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    .msg =
        (uint8_t *)
        "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6",
    .msg_len = 4 * 16,
};

const aes_test_case *aes_tests[] = {
    /* AES ECB */
    &aes128_ecb_enc_test_case_1, &aes128_ecb_dec_test_case_1,
    &aes192_ecb_enc_test_case_1, &aes192_ecb_dec_test_case_1,
    &aes256_ecb_enc_test_case_1, &aes256_ecb_dec_test_case_1,
    /* AES CBC */
    &aes128_cbc_enc_test_case_1, &aes128_cbc_dec_test_case_1,
    &aes192_cbc_enc_test_case_1, &aes192_cbc_dec_test_case_1,
    &aes256_cbc_enc_test_case_1, &aes256_cbc_dec_test_case_1,
    /* AES CTR */
    &aes128_ctr_enc_test_case_1, &aes128_ctr_dec_test_case_1,
    &aes192_ctr_enc_test_case_1, &aes192_ctr_dec_test_case_1,
    &aes256_ctr_enc_test_case_1, &aes256_ctr_dec_test_case_1,
};

#define MAX_TEST_BUF_LEN (4 * 16)

// FIXME: finish migration to userspace
int do_aes_test_vectors(int dma_in_desc, int dma_out_desc)
{
    uint32_t i,j;
    for (j = 0; j < sizeof(available_aes) / sizeof(aes_desc); j++) {
        for (i = 0; i < sizeof(aes_tests) / sizeof(aes_test_case *); i++) {
            uint8_t tmp[MAX_TEST_BUF_LEN];
            aes_context ctx;

#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
            dma_in_ok = dma_out_ok = 0;
#endif
            /* Sanity check */
            if (MAX_TEST_BUF_LEN < aes_tests[i]->exp_out_len) {
                printf("[AES self tests] %s: %s length failed :-(\n",
                       available_aes[j].name, aes_tests[i]->name);
                continue;
            }
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
            if (aes_init
                (&ctx, aes_tests[i]->key, aes_tests[i]->key_len,
                 aes_tests[i]->iv, aes_tests[i]->mode, aes_tests[i]->dir,
                 available_aes[j].type, (void *)dma_in_complete,
                 (void *)dma_out_complete, dma_in_desc, dma_out_desc)) {
                printf("[AES self tests] aes_init %s: %s failed :-(\n",
                       available_aes[j].name, aes_tests[i]->name);
                continue;
            }
#else
            if (aes_init
                (&ctx, aes_tests[i]->key, aes_tests[i]->key_len,
                 aes_tests[i]->iv, aes_tests[i]->mode, aes_tests[i]->dir,
                 available_aes[j].type, NULL, NULL, -1, -1)) {
                printf("[AES self tests] aes_init %s: %s failed :-(\n",
                       available_aes[j].name, aes_tests[i]->name);
                continue;
            }
#endif

            if (aes(&ctx, aes_tests[i]->msg, tmp, aes_tests[i]->exp_out_len,
                    dma_in_desc, dma_out_desc)) {
                printf("[AES self tests] aes %s: %s exec failed :-(\n",
                       available_aes[j].name, aes_tests[i]->name);
                continue;
            }
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
            if (available_aes[j].type == AES_HARD_DMA) {
                /* Wait until DMA transactions are finished */
                while ((dma_in_ok == 0) || (dma_out_ok == 0)) {
                    //printf("waiting for DMA...\n");
                };
            }
#endif
            if (memcmp(tmp, aes_tests[i]->exp_out, aes_tests[i]->exp_out_len)) {
                printf("[AES self tests] %s: %s result failed :-(\n",
                       available_aes[j].name, aes_tests[i]->name);
                continue;
            } else {
                printf("[AES self tests] %s: %s OK!\n", available_aes[j].name,
                       aes_tests[i]->name);
            }
        }
    }
    return 0;
}

#endif

#ifdef CONFIG_USR_LIB_AES_PERF
//#include "cycles_count.h"

typedef struct {
    const char *name;
    enum aes_key_len key_len;
} perf_key_len;

typedef struct {
    const char *name;
    enum aes_mode mode;
} perf_mode;

typedef struct {
    const char *name;
    enum aes_dir dir;
} perf_dir;

perf_key_len possible_perf_key_len[] = {
    {.name = "_AES128_",.key_len = KEY_128},
    {.name = "_AES192_",.key_len = KEY_192},
    {.name = "_AES256_",.key_len = KEY_256},
};

perf_mode possible_perf_mode[] = {
    {.name = "_ECB_",.mode = ECB},
    {.name = "_CBC_",.mode = CBC},
    {.name = "_CTR_",.mode = CTR},
};

perf_dir possible_perf_dir[] = {
    {.name = "_ENCRYPT_",.dir = ENCRYPT},
    {.name = "_DECRYPT_",.dir = DECRYPT},
};

#define PERF_SMALL_CHUNK 	32
#define PERF_MEDIUM_CHUNK	1024
#define PERF_BIG_CHUNK		4096


//uint32_t possible_perf_len[] = { 16, 32, 512, 1024, 2048, 4096, 8192, 16384, 32768, 40960, 49152 };
uint32_t possible_perf_len[] = { 16, 32, 512, 1024, 2048, 4096, 8192, 12288, 16384, 32768 };

#define MAX_PERF_CASE_NAME_LEN 128
typedef struct {
    char name[MAX_PERF_CASE_NAME_LEN];
    /* AES parameters */
    perf_key_len key_len;
    perf_mode mode;
    perf_dir dir;
    /* Message length */
    uint32_t msg_len;
} aes_perf_case;

aes_perf_case
    possible_aes_perf_case[(sizeof(possible_perf_key_len) /
                            sizeof(perf_key_len)) *
                           (sizeof(possible_perf_mode) / sizeof(perf_mode)) *
                           (sizeof(possible_perf_dir) / sizeof(perf_dir)) *
                           (sizeof(possible_perf_len) / sizeof(uint32_t))];

uint8_t msg[32768];

int generate_aes_test_performance_cases()
{
    unsigned int i, j, k, z;
    unsigned int index = 0;

    //FIXME: initial values corrupted ???

    for (i = 0; i < (sizeof(possible_perf_key_len) / sizeof(perf_key_len)); i++) {
        for (j = 0; j < (sizeof(possible_perf_mode) / sizeof(perf_mode)); j++) {
            for (k = 0; k < (sizeof(possible_perf_dir) / sizeof(perf_dir)); k++) {
                for (z = 0; z < (sizeof(possible_perf_len) / sizeof(uint32_t));
                     z++) {
                    uint32_t size = 0;
                    uint32_t len = 0;
                    /*****/
                    possible_aes_perf_case[index].key_len =
                        possible_perf_key_len[i];
                    possible_aes_perf_case[index].mode = possible_perf_mode[j];
                    possible_aes_perf_case[index].dir = possible_perf_dir[k];
                    possible_aes_perf_case[index].msg_len =
                        possible_perf_len[z];
                    /*****/
                    memset(possible_aes_perf_case[index].name, 0,
                           sizeof(possible_aes_perf_case[index].name));
                    if ((size +
                         strlen(possible_aes_perf_case[index].key_len.name)) >=
                        sizeof(possible_aes_perf_case[index].name)) {
                        goto error;
                    }
                    len = strlen(possible_aes_perf_case[index].key_len.name);
                    memcpy(possible_aes_perf_case[index].name + size,
                           possible_aes_perf_case[index].key_len.name, len);
                    size += strlen(possible_aes_perf_case[index].key_len.name);
                     /**/
                        if ((size +
                             strlen(possible_aes_perf_case[index].mode.name)) >=
                            sizeof(possible_aes_perf_case[index].name)) {
                        goto error;
                    }
                    len = strlen(possible_aes_perf_case[index].mode.name);
                    memcpy(possible_aes_perf_case[index].name + size,
                           possible_aes_perf_case[index].mode.name, len);
                    size += strlen(possible_aes_perf_case[index].mode.name);
                    if ((size +
                         strlen(possible_aes_perf_case[index].dir.name)) >=
                        sizeof(possible_aes_perf_case[index].name)) {
                        goto error;
                    }
                    len = strlen(possible_aes_perf_case[index].dir.name);
                    memcpy(possible_aes_perf_case[index].name + size,
                           possible_aes_perf_case[index].dir.name, len);
                    size += strlen(possible_aes_perf_case[index].dir.name);
                    index++;
                    /* Check for loop ending ... */
                    if (index ==
                        (sizeof(possible_aes_perf_case) /
                         sizeof(aes_perf_case))) {
                        return 0;
                    }
                }
            }
        }
    }

 error:
    return -1;
}

int do_aes_test_performance(int dma_in_desc, int dma_out_desc)
{
    unsigned int i, j;

    if (generate_aes_test_performance_cases()) {
        printf("[AES perf tests] Error when generating the test cases ...\n");
        goto error;
    }
    //TODO: no more needed in userspace
    //init_cycles_count();
    //start_cycles_count(); 

    for (j = 0; j < sizeof(available_aes) / sizeof(aes_desc); j++) {
        aes_context ctx;
        /* Dummy key and IV for performance measurement */
        uint8_t key[32] = { 0 };
        uint8_t iv[16] = { 0 };
//        uint32_t sizew = 0;
//        char ipc_buf[128];
        //uint8_t *msg = NULL;

     //   uint64_t start_systick = 0;
     //   uint64_t stop_systick = 0;

        for (i = 0;
             i < (sizeof(possible_aes_perf_case) / sizeof(aes_perf_case));
             i++) {
            dma_in_ok = dma_out_ok = 0;

            //reset_cycles_count();

            start_init = get_cycles();

#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
            if (aes_init
                (&ctx, key, possible_aes_perf_case[i].key_len.key_len, iv,
                 possible_aes_perf_case[i].mode.mode,
                 possible_aes_perf_case[i].dir.dir, available_aes[j].type,
                 (void *)dma_in_complete, (void *)dma_out_complete,
                dma_in_desc, dma_out_desc)) {
                printf("[AES perf tests] %s: %s init failed :-(\n",
                       available_aes[j].name, possible_aes_perf_case[i].name);
                continue;
            }
#else
            if (aes_init
                (&ctx, key, possible_aes_perf_case[i].key_len.key_len, iv,
                 possible_aes_perf_case[i].mode.mode,
                 possible_aes_perf_case[i].dir.dir, available_aes[j].type, NULL,
                 NULL, (void *)dma_out_complete), dma_in_desc, dma_out_desc) {
                printf("[AES perf tests] %s: %s init failed :-(\n",
                       available_aes[j].name, possible_aes_perf_case[i].name);
                continue;
            }
#endif
            end_init = get_cycles();
            //msg = NULL;
            // FIXME: we need an allocator!!!msg = malloc(possible_aes_perf_case[i].msg_len * sizeof(uint8_t));
            /* Zeroize the input */
            memset(msg, 0, possible_aes_perf_case[i].msg_len);
            //sys_get_systick(&start_systick);
            start_crypt = get_cycles();

            for(uint32_t z = 0; z < 10000; ++z) {
                if (aes(&ctx, msg, msg, possible_aes_perf_case[i].msg_len, dma_in_desc, dma_out_desc)) {
                    printf("[AES perf tests] %s: %s crypto failed :-(\n",
                            available_aes[j].name, possible_aes_perf_case[i].name);
                    //if(msg){
                    //FIXME: idem: allocator! free(msg, possible_aes_perf_case[i].msg_len);
                    //}
                    continue;
                }
#ifdef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
                if (available_aes[j].type == AES_HARD_DMA) {
                    /* Wait until DMA transactions are finished */
                    while ((dma_in_ok == 0) || (dma_out_ok == 0)) {
                        continue;
                    }
                }
            }
#endif
            end_crypt = get_cycles();
#if 0
            //sys_get_systick(&stop_systick);
            printf
                ("[AES perf tests] %s: %s took %x cycles for init, %x ticks, %x cycles/block %x ticks/block for crypto for chunks of size %x\n",
                 available_aes[j].name, possible_aes_perf_case[i].name,
                 (end_init - start_init), stop_systick - start_systick,
                 (end_crypt -
                  start_crypt) / (possible_aes_perf_case[i].msg_len / 16), (stop_systick - start_systick) / (possible_aes_perf_case[i].msg_len / 16),
                 possible_aes_perf_case[i].msg_len);
#endif
       uint32_t diff = end_crypt - start_crypt;
       uint32_t start = (uint32_t)start_crypt;
       uint32_t stop = (uint32_t)end_crypt;
       printf
                ("%s %s %x %x %x %x %x\n",
                 available_aes[j].name, possible_aes_perf_case[i].name,
                 diff / 10000, 
                 ((diff / ((possible_aes_perf_case[i].msg_len / 16) * 10000))),
                 start, stop,
                 possible_aes_perf_case[i].msg_len);
//       sys_ipc(IPC_SEND_ASYNC, id_benchlog, (logsize_t)sizew, ipc_buf);
#if 0
            printf
                ("%s:%s:%x:%x:%x:%x\n",
                 available_aes[j].name, possible_aes_perf_case[i].name,
                 possible_aes_perf_case[i].msg_len,
                 (start_crypt),
                 (end_crypt),
                 ((end_crypt -
                  start_crypt) / (possible_aes_perf_case[i].msg_len / 16)));
#endif
            //if(msg){
            //FIXME: idem: allocator !free(msg, possible_aes_perf_case[i].msg_len);
            //}

        }
    }

    return 0;

 error:
    return -1;
}

//#ifdef AES_TEST_PERFORMANCE_STLIB
#if 0
#if defined(__arm__)
#define USE_HW_AES
#define INCLUDE_ECB
#define INCLUDE_ENCRYPTION
#define INCLUDE_DECRYPTION
#include "stlib/inc/AES/aes.h"

int do_aes_test_performance_STLIB(void)
{
    AESECBctx_stt AESctx_st;
    /* outSize is for output size, retval is for return value */
    int32_t outSize, retval;
    uint8_t key[32] = { 0 };
    uint8_t iv[16] = { 0 };

    uint8_t *plaintext, *ciphertext;

    /* Initialize Context Flag with default value */
    AESctx_st.mFlags = E_SK_DEFAULT;
    /* Set Iv size to 16 */
    AESctx_st.mIvSize = 16;
    /* Set key size to 16 */
    AESctx_st.mKeySize = CRL_AES128_KEY;
    /* call init function */
    retval = AES_ECB_Encrypt_Init(&AESctx_st, key, NULL);
    if (retval != AES_SUCCESS) {
        printf("[AES perf tests] STLIB AES failed in INIT :-(\n");
        goto err;
    }

    /* Encrypt i bytes of plaintext. Put the output data in ciphertext and number 
       of written bytes in outSize */
    plaintext = malloc(8192 * sizeof(uint8_t));
    ciphertext = plaintext;
    retval =
        AES_ECB_Encrypt_Append(&AESctx_st, plaintext, 8192, ciphertext,
                               &outSize);
    if (retval != AES_SUCCESS) {
        printf("[AES perf tests] STLIB AES failed in ENCRYPT :-(\n");
        goto err;
    }

    /* Do the finalization call (in CBC it will not return any output) */
    retval = AES_ECB_Encrypt_Finish(&AESctx_st, ciphertext + outSize, &outSize);
    if (retval != AES_SUCCESS) {
    }

    return 0;
 err:
    return -1;
}

#endif
#endif

#endif
