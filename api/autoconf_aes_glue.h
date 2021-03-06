#ifndef __AUTOCONF_AES_GLUE_H__
#define __AUTOCONF_AES_GLUE_H__

#include "autoconf.h"

/* This is the glue to handle FW and DFU mode differenciation
 * in the config file.
 */
#ifndef CONFIG_USR_LIB_AES_PERF
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_PERF) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_PERF
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_PERF) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_PERF
#endif
#endif


#ifndef CONFIG_USR_LIB_AES_ALGO_UNMASKED
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_UNMASKED) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_UNMASKED) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED
#endif
#endif

#ifndef CONFIG_USR_LIB_AES_ALGO_UNMASKED_TABLE
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_UNMASKED_TABLE) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED_TABLE
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_UNMASKED_TABLE) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED_TABLE
#endif
#endif


#ifndef CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_UNMASKED_SIMPLE) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_UNMASKED_SIMPLE) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE
#endif
#endif



#ifndef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_ANSSI_MASKED) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_ANSSI_MASKED) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
#endif
#endif

#ifndef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_CRYP_SUPPORT) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_CRYP_SUPPORT) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT
#endif
#endif

#ifndef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_CRYP_SUPPORT_DMA) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_CRYP_SUPPORT_DMA) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_DMA
#endif
#endif

#ifndef CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
/**/
#if defined(CONFIG_USR_LIB_AES_DFU_ALGO_CRYP_SUPPORT_POLL) && defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
/**/
#elif defined(CONFIG_USR_LIB_AES_FW_ALGO_CRYP_SUPPORT_POLL) && !defined(MODE_DFU)
#define CONFIG_USR_LIB_AES_ALGO_CRYP_SUPPORT_POLL
#endif
#endif

#endif /* __AUTOCONF_AES_GLUE_H__ */
