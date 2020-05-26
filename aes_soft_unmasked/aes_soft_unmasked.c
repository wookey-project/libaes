#include "aes_soft_unmasked.h"

#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED

#if !defined(CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE)
  #error "CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE not defined! Please select it ..."
#endif

/**** Common helpers ************/
/* Memcpy helper */
static inline void local_copy(void *dst, const void *src, uint32_t n)
{
        const uint8_t *lsrc = (const uint8_t*)src;
        uint8_t *ldst = (uint8_t*)dst;
        uint32_t i;

        for (i = 0; i < n; i++) {
                *ldst = *lsrc;
                ldst++;
                lsrc++;
        }
}
/* Memset helper */
static inline void local_set(void *dst, uint8_t val, uint32_t n)
{
        uint8_t *ldst = (uint8_t*)dst;
        uint32_t i;

        for (i = 0; i < n; i++) {
                *ldst = val;
                ldst++;
        }
}

/* Useful macros */
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                          	 \
do {                                                    	 \
        (n) =     ( ((uint32_t) (b)[(i)    ]) << 24 )   	 \
                | ( ((uint32_t) (b)[(i) + 1]) << 16 )        \
                | ( ((uint32_t) (b)[(i) + 2]) <<  8 )        \
                | ( ((uint32_t) (b)[(i) + 3])       );       \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                  	   	\
do {                                            	   	\
        (b)[(i)    ] = (uint8_t) ( (n) >> 24 );      	\
        (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );      	\
        (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );      	\
        (b)[(i) + 3] = (uint8_t) ( (n)       );      	\
} while( 0 )
#endif
/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (uint8_t) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (uint8_t) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (uint8_t) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (uint8_t) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/* S-Box */
static const uint8_t sbox[256] = {
     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Inverse S-Box */
static const uint8_t inv_sbox[256] = {
     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE
/* Non-tabulated and simple AES */

/* This is a very straightforward and basic implementation of AES (128, 192 and 256) */

static const uint8_t rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

/* AES primitives *******************************************************/
/************************************************************************/
/* Multiplication over Galois field */
#define xtime(x) (((x)<<1) ^ ((((x)>>7) & 1) * 0x1b))
static inline uint8_t gmul(uint8_t x, uint8_t y){
	return ((((y & 1) * x) ^ (((y>>1) & 1) * xtime(x)) ^ (((y>>2) & 1) * xtime(xtime(x))) ^ (((y>>3) & 1) * xtime(xtime(xtime(x)))) ^ (((y>>4) & 1) * xtime(xtime(xtime(xtime(x))))))) & 0xff;
}

static inline void add_rkey(uint8_t *state, const uint8_t *rkey){
	uint32_t i;
	for(i = 0; i < 16; i++){
		state[i] ^= rkey[i];
	}
}

static inline void sub_bytes(uint8_t *state, uint8_t dir){
	uint32_t i;
	for(i = 0; i < 16; i++){
		if(dir == AES_SOFT_UNMASKED_ENC){
			state[i] = sbox[state[i]];
		}
		else{
			state[i] = inv_sbox[state[i]];
		}
	}
}

static inline void shift_rows(uint8_t *state, uint8_t dir){
	uint8_t s[16];
	local_copy(s, state, 16);

	if(dir == AES_SOFT_UNMASKED_ENC){
		state[1] = s[5]; state[2] = s[10]; state[3] = s[15];
		state[5] = s[9]; state[6] = s[14]; state[7] = s[3];
		state[9] = s[13]; state[10] = s[2]; state[11] = s[7];
		state[13] = s[1]; state[14] = s[6]; state[15] = s[11];
	}
	else{
		state[1] = s[13]; state[2] = s[10]; state[3] = s[7];
		state[5] = s[1]; state[6] = s[14]; state[7] = s[11];
		state[9] = s[5]; state[10] = s[2]; state[11] = s[15];
		state[13] = s[9]; state[14] = s[6]; state[15] = s[3];
	}
}

static inline void sub_bytes_sr(uint8_t *state, uint8_t dir){
	uint8_t s[16];
	local_copy(s, state, 16);
	if(dir == AES_SOFT_UNMASKED_ENC){
		/* Subbytes then Shiftrows */
		state[0]  = sbox[s[0]];
		state[1]  = sbox[s[5]];
		state[2]  = sbox[s[10]];
		state[3]  = sbox[s[15]];
		/**/
		state[4]  = sbox[s[4]];
		state[5]  = sbox[s[9]];
		state[6]  = sbox[s[14]];
		state[7]  = sbox[s[3]];
		/**/
		state[8]  = sbox[s[8]];
		state[9]  = sbox[s[13]];
		state[10] = sbox[s[2]];
		state[11] = sbox[s[7]];
		/**/
		state[12] = sbox[s[12]];
		state[13] = sbox[s[1]];
		state[14] = sbox[s[6]];
		state[15] = sbox[s[11]];
	}
	else{
		/* Shiftrows then InvSubbytes */
		state[0]  = inv_sbox[s[0]];
		state[5]  = inv_sbox[s[1]];
		state[10] = inv_sbox[s[2]];
		state[15] = inv_sbox[s[3]];
		/**/
		state[4]  = inv_sbox[s[4]];
		state[9]  = inv_sbox[s[5]];
		state[14] = inv_sbox[s[6]];
		state[3]  = inv_sbox[s[7]];
		/**/
		state[8]  = inv_sbox[s[8]];
		state[13] = inv_sbox[s[9]];
		state[2]  = inv_sbox[s[10]];
		state[7]  = inv_sbox[s[11]];
		/**/
		state[12] = inv_sbox[s[12]];
		state[1]  = inv_sbox[s[13]];
		state[6]  = inv_sbox[s[14]];
		state[11] = inv_sbox[s[15]];
	}
}



static const uint8_t mixcol_matrix[4]    = { 2, 1, 1, 3 };
static const uint8_t invmixcol_matrix[4] = { 14, 9, 13, 11 };

#define MC_UNROLLED
static inline void mix_columns(uint8_t *state, uint8_t dir){
	const uint8_t *matrix;
	uint8_t s[16];

	if(dir == AES_SOFT_UNMASKED_ENC){
		matrix = mixcol_matrix;
	}
	else{
		matrix = invmixcol_matrix;
	}
	local_copy(s, state, 16);
#ifndef MC_UNROLLED
	uint32_t i, base;
	for(i = 0; i < 4; i++){
		base = 4 * i;
		state[base+0]  = gmul(s[base+0], matrix[0]) ^ gmul(s[base+3], matrix[1]) ^ gmul(s[base+2], matrix[2]) ^ gmul(s[base+1], matrix[3]);
		state[base+1]  = gmul(s[base+1], matrix[0]) ^ gmul(s[base+0], matrix[1]) ^ gmul(s[base+3], matrix[2]) ^ gmul(s[base+2], matrix[3]);
		state[base+2]  = gmul(s[base+2], matrix[0]) ^ gmul(s[base+1], matrix[1]) ^ gmul(s[base+0], matrix[2]) ^ gmul(s[base+3], matrix[3]);
		state[base+3]  = gmul(s[base+3], matrix[0]) ^ gmul(s[base+2], matrix[1]) ^ gmul(s[base+1], matrix[2]) ^ gmul(s[base+0], matrix[3]);
	}
#else
	state[0]  = gmul(s[0], matrix[0]) ^ gmul(s[3], matrix[1]) ^ gmul(s[2], matrix[2]) ^ gmul(s[1], matrix[3]);
	state[1]  = gmul(s[1], matrix[0]) ^ gmul(s[0], matrix[1]) ^ gmul(s[3], matrix[2]) ^ gmul(s[2], matrix[3]);
	state[2]  = gmul(s[2], matrix[0]) ^ gmul(s[1], matrix[1]) ^ gmul(s[0], matrix[2]) ^ gmul(s[3], matrix[3]);
	state[3]  = gmul(s[3], matrix[0]) ^ gmul(s[2], matrix[1]) ^ gmul(s[1], matrix[2]) ^ gmul(s[0], matrix[3]);
	/**/
	state[4]  = gmul(s[4], matrix[0]) ^ gmul(s[7], matrix[1]) ^ gmul(s[6], matrix[2]) ^ gmul(s[5], matrix[3]);
	state[5]  = gmul(s[5], matrix[0]) ^ gmul(s[4], matrix[1]) ^ gmul(s[7], matrix[2]) ^ gmul(s[6], matrix[3]);
	state[6]  = gmul(s[6], matrix[0]) ^ gmul(s[5], matrix[1]) ^ gmul(s[4], matrix[2]) ^ gmul(s[7], matrix[3]);
	state[7]  = gmul(s[7], matrix[0]) ^ gmul(s[6], matrix[1]) ^ gmul(s[5], matrix[2]) ^ gmul(s[4], matrix[3]);
	/**/
	state[8]  = gmul(s[8], matrix[0]) ^ gmul(s[11], matrix[1]) ^ gmul(s[10], matrix[2]) ^ gmul(s[9], matrix[3]);
	state[9]  = gmul(s[9], matrix[0]) ^ gmul(s[8], matrix[1]) ^ gmul(s[11], matrix[2]) ^ gmul(s[10], matrix[3]);
	state[10] = gmul(s[10], matrix[0]) ^ gmul(s[9], matrix[1]) ^ gmul(s[8], matrix[2]) ^ gmul(s[11], matrix[3]);
	state[11] = gmul(s[11], matrix[0]) ^ gmul(s[10], matrix[1]) ^ gmul(s[9], matrix[2]) ^ gmul(s[8], matrix[3]);
	/**/
	state[12] = gmul(s[12], matrix[0]) ^ gmul(s[15], matrix[1]) ^ gmul(s[14], matrix[2]) ^ gmul(s[13], matrix[3]);
	state[13] = gmul(s[13], matrix[0]) ^ gmul(s[12], matrix[1]) ^ gmul(s[15], matrix[2]) ^ gmul(s[14], matrix[3]);
	state[14] = gmul(s[14], matrix[0]) ^ gmul(s[13], matrix[1]) ^ gmul(s[12], matrix[2]) ^ gmul(s[15], matrix[3]);
	state[15] = gmul(s[15], matrix[0]) ^ gmul(s[14], matrix[1]) ^ gmul(s[13], matrix[2]) ^ gmul(s[12], matrix[3]);
#endif
}

static inline void sched(uint8_t *in, uint8_t n){
	/* Rotate word, apply sbox and rcon */
	uint8_t t = in[0];
	in[0] = sbox[in[1]] ^ rcon[n];
	in[1] = sbox[in[2]];
	in[2] = sbox[in[3]];
	in[3] = sbox[t];

	return;
}

/* Encryption key schedule */
int aes_soft_unmasked_setkey_enc(aes_soft_unmasked_context *ctx, const uint8_t *key, uint32_t keybits)
{
	uint32_t size = (keybits / 8);
	uint8_t t[4];
	uint8_t n = 1;
	uint32_t keysize = (keybits / 8);

	if((ctx == NULL) || (key == NULL)){
		goto err;
	}
	if(keybits == 128){
		ctx->nr = 10;
	}
	else if(keybits == 192){
		ctx->nr = 12;
	}
	else if(keybits == 256){
		ctx->nr = 14;
	}
	else{
		goto err;
	}
	/* Perform the key schedule */
	local_copy(&ctx->rk, key, keysize);
	while(size < (16*(ctx->nr + 1))){
		local_copy(t, &ctx->rk[size - 4], 4);
		if((size % keysize) == 0) {
			sched(t, n);
			n++;
		}
		/* Extra sbox for 256 bit key */
		if((keybits == 256) && ((size % keysize) == 16)){
			t[0] = sbox[t[0]]; t[1] = sbox[t[1]];
			t[2] = sbox[t[2]]; t[3] = sbox[t[3]];
		}
		ctx->rk[size]     = ctx->rk[size - keysize]     ^ t[0];
		ctx->rk[size + 1] = ctx->rk[size - keysize + 1] ^ t[1];
		ctx->rk[size + 2] = ctx->rk[size - keysize + 2] ^ t[2];
		ctx->rk[size + 3] = ctx->rk[size - keysize + 3] ^ t[3];
		size += 4;
	}

	return 0;
err:
	return -1;
}

/* Encryption primitive */
int aes_soft_unmasked_enc(aes_soft_unmasked_context *ctx, const uint8_t data_in[16], uint8_t data_out[16])
{
	uint32_t r;
	/* Our local state */
	uint8_t state[16];
	uint32_t dir = AES_SOFT_UNMASKED_ENC;

	if((ctx == NULL) || (data_in == NULL) || (data_out == NULL)){
		goto err;
	}
	/* Sanity check for array access */
	if((16 * (ctx->nr + 1)) > sizeof(ctx->rk)){
		goto err;
	}
	local_copy(state, data_in, 16);

	/* Initial add round key */
	add_rkey(state, &ctx->rk[0]);

	/* All our rounds except the last one */
	for(r = 1; r < ctx->nr; r++){
		sub_bytes_sr(state, dir);
		mix_columns(state, dir);
		add_rkey(state, &ctx->rk[16*r]);
	}
	/* Last round without mixcolumns */
	sub_bytes_sr(state, dir);
	add_rkey(state, &ctx->rk[16*r]);

	/* Copy back state to ciphertext */
	local_copy(data_out, state, 16);

	/* Clean stuff */
	local_set(state, 0, sizeof(state));

	return 0;

err:
	return -1;
}

/* Decryption key schedule */
int aes_soft_unmasked_setkey_dec(aes_soft_unmasked_context *ctx, const uint8_t *key, uint32_t keybits)
{
	/* Encryption and decryption have the same key schedule */
	return aes_soft_unmasked_setkey_enc(ctx, key, keybits);
}

/* Decryption primitive */
int aes_soft_unmasked_dec(aes_soft_unmasked_context *ctx, const uint8_t data_in[16], uint8_t data_out[16])
{
	uint32_t r;
	/* Our local state */
	uint8_t state[16];
	uint32_t dir = AES_SOFT_UNMASKED_DEC;

	if((ctx == NULL) || (data_in == NULL) || (data_out == NULL)){
		goto err;
	}
	/* Sanity check for array access */
	if((16 * (ctx->nr + 1)) > sizeof(ctx->rk)){
		goto err;
	}
	local_copy(state, data_in, 16);

	r = ctx->nr;
	/* Initial add round key */
	add_rkey(state, &ctx->rk[16*r]);
	r--;

	/* All our rounds except the last one */
	while(r > 0){
		sub_bytes_sr(state, dir);
		add_rkey(state, &ctx->rk[16*r]);
		mix_columns(state, dir);
		r--;
	}
	/* Last round without mixcolumns */
	sub_bytes_sr(state, dir);
	add_rkey(state, &ctx->rk[0]);

	/* Copy back state to plaintext */
	local_copy(data_out, state, 16);

	/* Clean stuff */
	local_set(state, 0, sizeof(state));

	return 0;

err:
	return -1;
}
#endif /* CONFIG_USR_LIB_AES_ALGO_UNMASKED_SIMPLE */


#endif /* CONFIG_USR_LIB_AES_ALGO_UNMASKED */


