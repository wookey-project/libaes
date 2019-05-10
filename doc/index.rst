.. _lib_aes:

the AES library
===============

.. contents::

the libaes project aim to implement the AES (Advanced Encryption Standard).

This library supports:

   * Fully software, masked implementation (designed to be protected against side
     channel attacks
   * Hardware based implementation, based on an underlying hardware cryptographic
     coprocessor through an existing dedicated driver

By now, the libaes support the following key length:

   * AES 128
   * AES 192
   * AES 256

The libaes also supports the following AES modes:

   * AES ECB
   * AES CBC
   * AES CTR

Overview
--------

Principles
""""""""""

TODO: basic AES principles and why here

Limitations
"""""""""""

TODO: the library limitations

The libdaes API
--------------

Initializing libAES
"""""""""""""""""""

Initializing libAES is done with the following API ::

   #include "aes.h"

   enum aes_type {
       AES_SOFT_ANSSI_MASKED = 1,
       AES_HARD_NODMA = 2,
       AES_HARD_DMA = 3
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


   int aes_init(      aes_context        *aes_ctx,
                const unsigned char      *key,
                      enum aes_key_len    key_len,
                const unsigned char      *iv,
                      enum aes_mode       mode,
                      enum aes_dir        dir,
                      enum aes_type       type,
                      user_dma_handler_t  dma_in_complete,
                      user_dma_handler_t  dma_out_complete,
                      int                 dma_in_desc,
                      int                 dma_out_desc);

The AES initialization function does the following:

   * initialize the AES context, by:
      * setting the AES key and key len
      * setting the IV (in AES mode requiring IV)
      * setting the AES direction (encryption or direction)
      * setting the AES type
      * TODO continue doc


AES data (de/en)cryption
""""""""""""""""""""""""

