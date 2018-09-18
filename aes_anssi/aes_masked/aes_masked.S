/* AES-128 Encryption first order masking 
* v3.11.1 : Affine version of AES 
* Two random bytes (rin and rout) are used during the subbyte operation (constant for an encryption).
* State2 is 16 different random bytes that are different for each round ShiftRows and MixColumns operations 
* Modifications : Roll some functions (380 cycles lost)
* cycles before :  24 837 -  9 034 = 15 803
* cycles after  :  25 217 -  9 034 = 16 183
*/

#if defined(__CC_ARM)       // Keilo
    #define CODESECT AREA     MYCODE, CODE, READONLY, ALIGN=2
    #define DATASECT AREA     MYDATA, DATA, READWRITE
    #define MYLABEL
	#define MYBYTE DCB
	#define MYWORD DCW
	GBLA count                  ; declare local variable	

MACRO
ldr_addr $reg, $val
	movw $reg, #:lower16:$val
	movt $reg, #:upper16:$val
MEND
 	
#elif defined (__GNUC__)    // GCC
    #define THUMB .thumb
    #define CODESECT .section .text
	#define DATASECT .section .data
    #define EXPORT .global
    #define PROC :
    #define MYLABEL :
    #define ENDP
    #define END
	#define MYBYTE .byte
	#define MYWORD .word
	.syntax unified
	.cpu cortex-m4
	.fpu softvfp
	.thumb
    .syntax unified
#define LOCAL .local
#define ALIGN(a) .align(a)

.macro ldr_addr reg, val
	movw \reg, #:lower16:\val
	movt \reg, #:upper16:\val
.endm
#endif


	DATASECT
LOCAL state, stat2, key_state, sbox, sboxMasked, rcon_rnd, rcon

ALIGN(4)
state    MYLABEL	MYBYTE 		0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
state2   MYLABEL	MYBYTE 		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00




//Table of 11 key state, one for each round (the first one is the master key)
key_state MYLABEL
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF


// For each round, this value corresponds to the current key multiplied by the byte rmult
key_mstate MYLABEL
	MYBYTE 	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	


// Table to store the new Sbox computed from the byte rmult and the original Sbox
sboxMasked MYLABEL
    MYBYTE    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22
	

//	Table of multiplied number by rmult (for each round the derivated key will be multiplied by rmult)
GTab MYLABEL
    MYBYTE    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    MYBYTE    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22	

// rin and rout are the bytes used to mask in the SubByte operation.
rin  	MYLABEL		MYBYTE 		0x0f, 0x0f, 0x0f, 0x0f
rout 	MYLABEL		MYBYTE 		0xe0, 0xe0, 0xe0, 0xe0
	
// rmult has to be different from 0, it the multiplied byte of the affine representation
rmult	MYLABEL		MYBYTE  	0x0f



	CODESECT
	EXPORT anssi_aes_masked

// Original AES Sbox
sbox MYLABEL
    MYBYTE    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    MYBYTE    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    MYBYTE    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    MYBYTE    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    MYBYTE    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    MYBYTE    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    MYBYTE    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    MYBYTE    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    MYBYTE    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    MYBYTE    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    MYBYTE    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    MYBYTE    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    MYBYTE    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    MYBYTE    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    MYBYTE    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    MYBYTE    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16


rcon MYLABEL
	MYBYTE    0x01,0x00,0x00,0x00
	MYBYTE    0x02,0x00,0x00,0x00
	MYBYTE    0x04,0x00,0x00,0x00
	MYBYTE    0x08,0x00,0x00,0x00
	MYBYTE    0x10,0x00,0x00,0x00
	MYBYTE    0x20,0x00,0x00,0x00
	MYBYTE    0x40,0x00,0x00,0x00
	MYBYTE    0x80,0x00,0x00,0x00
	MYBYTE    0x1b,0x00,0x00,0x00
	MYBYTE    0x36,0x00,0x00,0x00

	
// Table of inverses
Inverse MYLABEL
	MYBYTE   1,   1, 141, 246, 203,  82, 123, 209, 232,  79,  41, 192, 176, 225, 229, 199
	MYBYTE 116, 180, 170,  75, 153,  43,  96,  95,  88,  63, 253, 204, 255,  64, 238, 178
	MYBYTE  58, 110,  90, 241,  85,  77, 168, 201, 193,  10, 152,  21,  48,  68, 162, 194
	MYBYTE  44,  69, 146, 108, 243,  57, 102,  66, 242,  53,  32, 111, 119, 187,  89,  25 
	MYBYTE  29, 254,  55, 103,  45,  49, 245, 105, 167, 100, 171,  19,  84,  37, 233,   9
	MYBYTE 237,  92,   5, 202,  76,  36, 135, 191,  24,  62,  34, 240,  81, 236,  97,  23
	MYBYTE  22,  94, 175, 211,  73, 166,  54,  67, 244,  71, 145, 223,  51, 147,  33,  59
	MYBYTE 121, 183, 151, 133,  16, 181, 186,  60, 182, 112, 208,   6, 161, 250, 129, 130 
	MYBYTE 131, 126, 127, 128, 150, 115, 190,  86, 155, 158, 149, 217, 247,   2, 185, 164
	MYBYTE 222, 106,  50, 109, 216, 138, 132, 114,  42,  20, 159, 136, 249, 220, 137, 154
	MYBYTE 251, 124,  46, 195, 143, 184, 101,  72,  38, 200,  18,  74, 206, 231, 210,  98
	MYBYTE  12, 224,  31, 239,  17, 117, 120, 113, 165, 142, 118,  61, 189, 188, 134,  87
	MYBYTE  11,  40,  47, 163, 218, 212, 228,  15, 169,  39,  83,   4,  27, 252, 172, 230 
	MYBYTE 122,   7, 174,  99, 197, 219, 226, 234, 148, 139, 196, 213, 157, 248, 144, 107
	MYBYTE 177,  13, 214, 235, 198,  14, 207, 173,   8,  78, 215, 227,  93,  80,  30, 179
	MYBYTE  91,  35,  56,  52, 104,  70,   3, 140, 221, 156, 125, 160, 205,  26,  65,   6


	
// table representing the field multiplication by 2
xtime MYLABEL
	MYBYTE 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e
	MYBYTE 0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e
	MYBYTE 0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e
	MYBYTE 0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e
	MYBYTE 0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e
	MYBYTE 0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe
	MYBYTE 0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde
	MYBYTE 0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe
	MYBYTE 0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05
	MYBYTE 0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25
	MYBYTE 0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45
	MYBYTE 0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65
	MYBYTE 0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85
	MYBYTE 0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5
	MYBYTE 0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5
	MYBYTE 0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5



// Two Tables to process a field multplication over GF(256): a*b = alog (log(a) + log(b) mod 255)
LogTable MYLABEL
	MYBYTE   0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3 
	MYBYTE 100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193 
	MYBYTE 125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120 
	MYBYTE 101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142 
	MYBYTE 150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56 
	MYBYTE 102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16 
	MYBYTE 126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186 
	MYBYTE  43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87 
	MYBYTE 175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232 
	MYBYTE  44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160 
	MYBYTE 127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183 
	MYBYTE 204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157 
	MYBYTE 151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209 
	MYBYTE  83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171 
	MYBYTE  68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165 
	MYBYTE 103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7 



ALogTable MYLABEL
	MYBYTE   1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53 
	MYBYTE  95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170 
	MYBYTE 229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49 
	MYBYTE  83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205 
	MYBYTE  76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136 
	MYBYTE 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154 
	MYBYTE 181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163 
	MYBYTE 254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160 
	MYBYTE 251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65 
	MYBYTE 195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117 
	MYBYTE 159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128 
	MYBYTE 155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84 
	MYBYTE 252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202 
	MYBYTE  69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14 
	MYBYTE  18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23 
	MYBYTE  57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1 


/************************************************************************
* Compute_GTab : Computation of multiplied number by rmult stored in GTab
* r2, r3, r4, r5, r6, r7 = local variables
* Unused : r0, r1, r8, r9, r10, r11, r12
*/

Compute_GTab MYLABEL
	ldr_addr r4, LogTable		// r4 = @LogTable
	add r5, r7, r4		    	// r5 = @LogTable[rmult] 
	ldrb r7, [r5] 		    	// r7 = LogTable[rmult] then r7 = log (rmult)
   	movw r5, #:lower16:ALogTable	// r5 = @ALogTable
	movt r5, #:upper16:ALogTable
   	movw r3, #:lower16:GTab		// r3 = @GTab
	movt r3, #:upper16:GTab
	
    add  r4, r4, #0x01			// r4 = @LogTable + 1 ; inc r4 since the case x = 0 is treated out of the loop
    mov  r6, #0					// r6 = 0
	strb r6, [r3], #01			// r6 = GTab[1]; r3 =@GTab[2] 
	
	// loop for x=1 to x=255
#if defined(__CC_ARM)       // Keil
count   SETA    1    		// set the arithmetic value count to 1        
    WHILE   count <= 255    
count   SETA    count+1      
#elif defined (__GNUC__)    // GCC
    .rept 255
#endif

    ldrb r6, [r4], #0x01    // r6  = log (x)
    add  r6, r7				// r6  = log (x) + log (rmult)	
    lsr  r2, r6, #8         // r2 = 1 if r6>255 and 0 otherwise  ; r11 = carry
    add  r6, r2             // r6 =  log (x) + log (rmult) + carry
    and  r6, r6, #0xFF      // r6 = [log x + log(rmult)] mod(255)
   
    add  r6, r6, r5			// r6 = @(ALogTable + [log x + log(rmult)] mod(255))
    ldrb r6,[r6]	    	// r6 = x * rmult
    strb r6, [r3], #01		// store x

#if defined(__CC_ARM)       // Keil
	WEND
#elif defined (__GNUC__)    // GCC
    .endr
#endif	

	bx LR
	
/************************************************************************
* Load_data
* r0, r2, r3, r4, r5, r6, r7 = local variables
* Unused : r1, r8, r9, r11, r12
* 
*/

Load_data MYLABEL
	// Load message (r0)	
	movw r3, #:lower16:state	// r3 = @state
	movt r3, #:upper16:state
	ldm r0, {r4, r5, r6, r10}
	stm r3, {r4, r5, r6, r10}

	// Load random (r2)		
	movw r10, #:lower16:state2	// r10 = @state2
	movt r10, #:upper16:state2
	ldm r2, {r4, r5, r6, r7}
	stm r10, {r4, r5, r6, r7}
	
	// Load rin 
	add r2, #0x10				// r2 = @random + 16 = @random[16] 				
	movw r7, #:lower16:rin		// r7 = @rin
	movt r7, #:upper16:rin
	ldrb r5, [r2],#0x1			// r5 = random[16] 
	strb r5, [r7],#0x1			// rin[0]; r7 = @rin+1*8; rin[i] is a byte.
	strb r5, [r7], #0x1			// rin[1] = random[16] 
	strb r5, [r7], #0x1			// rin[2] = random[16] 
	strb r5, [r7]				// rin[3] = random[16] then rin = random[16]|random[16]|random[16]|random[16]   
	
	// Load rout			
	movw r7, #:lower16:rout		// r7 = @rout
	movt r7, #:upper16:rout
	ldrb r5, [r2], #0x1			// r5 = random[17]
	strb r5, [r7], #0x1			// rout[0] = random[17] 
	strb r5, [r7], #0x1		    // rout[1] = random[17] 
	strb r5, [r7], #0x1			// rout[2] = random[17]	
	strb r5, [r7]				// rout[3] = random[17]	

	// Load rmult
	movw r5, #:lower16:rmult	// r5 = @rmult
	movt r5, #:upper16:rmult
	ldrb r7, [r2]				// r7 = random[18] 
	strb r7, [r5]				// rmult = random[18] 
	bx LR


/************************************************************************
* Compute_Affine_sboxMasked : It computes the masked version of the sbox
* sboxMasked(y) = sbox(y xor R) xor R' (R et R' = valeurs aléatoires) 
* r1, r2, r3, r4, r6, r7, r8, r12 = internal values 
* Unused register : r9, r10, r11
*/

Compute_Affine_sboxMasked MYLABEL
   movw r2, #:lower16:sbox			// r2  = @sbox
   movt r2, #:upper16:sbox
			
   movw r3, #:lower16:sboxMasked	// r3  = @sboxMasked
   movt r3, #:upper16:sboxMasked
	       		
   movw r12, #:lower16:GTab		// r12 = @GTab
   movt r12, #:upper16:GTab
   mov r4, r12         				// r4  = @GTab
         
   movw r8, #:lower16:rin			// r8 = @rin
   movt r8, #:upper16:rin  
   ldr  r1, [r8]					// r1 = rin
		
   movw r6, #:lower16:rout			// r6 = @rout
   movt r6, #:upper16:rout
   ldrb r8, [r6]					// r8 = rout
   
    #if defined(__CC_ARM)      // Keil
count   SETA    1    		// set the arithmetic value count to 1        
    WHILE   count <= 64    
count   SETA    count+1      
#elif defined (__GNUC__)    // GCC
    .rept 64
#endif  
  
//loop_MSubBytes MYLABEL		
   ldr r6, [r4], #4         // r6 = (y[3+4i] * rmult)||...||(y[0+4i] * rmult)   
   eor r6, r6, r1		    // r6 = (y[3+4i] * rmult xor rin)||...||(y[0+4i] * rmult xor rin) = G(3+4i)||...|G(0+4i)|

   and  r0, r6, #0xff		// r7 = r6[0]
   add  r0, r0, r3			// r0 = @(SboxMasked + G(0+4i))				
 
   add  r7, r2, #0			// r7 = @(Sbox       + 0 + 4i)
   ldrb r7, [r7]			// r7 = Sbox(0+4i) 
   
   add  r7, r7, r12         // r4 = @(GTab + Sbox(0+4i)) 
   ldrb r7, [r7]            // r7 = Sbox(0+4i)*rmult
   eor  r7, r8 				// r7 = (Sbox(0+4i)*rmult xor rout)
   strb r7, [r0]			// sboxMasked [G(0+4i)] = Sbox(0+4i)*rmult xor rout

   lsr  r0, r6,#8			// r6 = r6 >> 8
   
   and  r0, r0, #0xff		// r0 = r6[0]
   add  r0, r3, r0			// r0 = @(SboxMasked + G(1+4i))				
   add  r7, r2, #1			// r7 = @(Sbox       + 1 + 4i)
   ldrb r7, [r7]			// r7  = Sbox(1+4i) 
   add  r7, r12, r7         // r7  = @(GTab + Sbox(1+4i)) 
   ldrb r7, [r7]            // r7  = Sbox(1+4i)*rmult
   eor  r7, r8 				// r7 = (Sbox(1+4i)*rmult xor rout)
   strb r7, [r0]			// sboxMasked [G(1+4i)] = Sbox(1+4i)*rmult xor rout

   lsr  r0, r6, #16
   and  r0, r0, #0xff
   add  r0, r0, r3			// r0 = @(SboxMasked + G(2+4i))				

   add  r7, r2, #2			// r7 = @(Sbox       + 2 + 4i)
   ldrb r7, [r7]			// r7  = Sbox(2+4i)

   add  r7, r7, r12         // r7  = @(GTab + Sbox(2+4i)) 
   ldrb r7, [r7]            // r7  = Sbox(2+4i)*rmult
   eor  r7, r8 				// r7 = (Sbox(2+4i)*rmult xor rout)
   strb r7, [r0]			// sboxMasked [G(2+4i)] = Sbox(2+4i)*rmult xor rout

   lsr  r0, r6,#24
   and  r0, r0, #0xff
   add  r0, r0, r3			// r0 = @(SboxMasked + G(3+4i))				

   add  r7, r2, #3			// r7 = @(Sbox       + 3 + 4i)
   ldrb r7, [r7]			// r7  = Sbox(3+4i)
 
   add  r7, r7, r12         // r4  = @(GTab + Sbox(3+4i)) 
   ldrb r7, [r7]            // r7  = Sbox(3+4i)*rmult 
   eor  r7, r8 				// r7 = (Sbox(3+4i)*rmult xor rout)
   strb r7, [r0]			// sboxMasked [G(3+4i)] = Sbox(3+4i)*rmult xor rout
   
   add r2, r2, #4
  
	#if defined(__CC_ARM)       // Keil
		WEND
	#elif defined (__GNUC__)    // GCC
		.endr
	#endif
   bx LR 

	
/************************************************************************
* SubBytesWithMask : It modifies only state
* r3 = @state
* r4, r5, r6, r7, r8, r10 = local variables
* Unused : r0, r1, r2, r9, r11, r12
*/
SubBytesWithMask MYLABEL
	movw r10, #:lower16:state2	// r10 = @state2
	movt r10, #:upper16:state2
    	
	movw r8, #:lower16:sboxMasked	// r8 = @sboxMasked
	movt r8, #:upper16:sboxMasked

	mov r5, r10						// r5 = @state2
#if defined(__CC_ARM)       		// Keil
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 16     
count   SETA    count+1      
#elif defined (__GNUC__)    		// GCC
    .rept 16
#endif
   ldrb r4,[r3]						// r4 = State[i]
   ldrb r6,[r5]						// r6 = State2[i]
   eor  r4, r6 						// r4 = State[i] xor State2[i]
   add  r4, r8						// r4 = @ of the value sboxMasked[State[i] xor State2[i]]  
   ldrb r7, [r4]					// r7 = sboxMasked[State[i] xor State2[i]]
   eor  r7, r6 						// r7 = sboxMasked[State[i] xor State2[i]] xor State2[i]  
   strb r7, [r3],#01				// store the new masked value in r7 in State[i] 
   add  r5, #0x1					// go to the next byte
	#if defined(__CC_ARM)       	// Keil
		WEND
	#elif defined (__GNUC__)    	// GCC
		.endr
	#endif
	sub r3, #0x10
	// end 
	
	
	// Xor_word				state[i] = state[i] xor rout (--> SB(state[i]))	
	movw r7, #:lower16:rout			// r7 = @rout
	movt r7, #:upper16:rout
	
	ldr r5, [r7]					// r5 = wordB
#if defined(__CC_ARM)       		// Keil
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 4    
count   SETA    count+1      
#elif defined (__GNUC__)    		// GCC
    .rept 4
#endif

	ldr  r6, [r3]					// r6 = state[count; count + 3]
	eor  r6, r5						// r6 = state[count; count + 3] xor WordB
	str  r6, [r3], #0x4				// save r6 in @state[count; count + 3] and go to the next state word
	
#if defined(__CC_ARM)       		// Keil
	WEND
#elif defined (__GNUC__)    		// GCC
	.endr
#endif
	
	
    bx LR
   
   
 /************************************************************************
* ShiftRowsWithMask : It modifies state and state2
* r3 = @state
* used : r4, r5, r6, r7,
*/
ShiftRowsWithMasked MYLABEL	
	add r3, #0x1					// r3 = @state +1
	ldrb r4, [r3], #0x4				// r4 = state[1] --> s10
	ldrb r5, [r3], #0x4				// r5 = state[5] --> s11
	ldrb r6, [r3], #0x4				// r6 = state[9] --> s12
	ldrb r7, [r3]					// r7 = state[13] --> s13

	sub r3, #0xC					// come back to the fist byte @

	strb r5,[r3], #0x4				// state[1] = state[5]
	strb r6,[r3], #0x4				// state[5] = state[9]
	strb r7,[r3], #0x4				// state[9] = state[13]
	strb r4,[r3]					// state[13] = state[1]

	sub r3, #0xB
	ldrb r4, [r3], #0x4				// r4 = state[2] --> s20
	ldrb r5, [r3], #0x4				// r5 = state[6] --> s21
	ldrb r6, [r3], #0x4				// r6 = state[10] --> s22
	ldrb r7, [r3]					// r7 = state[12] --> s23

	sub r3, #0xC
	strb r6,[r3], #0x4				//state[2] = state[10] 
	strb r7,[r3], #0x4				//state[6] = state[12] 
	strb r4,[r3], #0x4				//state[10] = state[2] 
	strb r5,[r3]					//state[12] = state[6]

	sub r3, #0xB
	ldrb r4, [r3], #0x4				// r4 = state[3] --> s30	
	ldrb r5, [r3], #0x4				// r5 = state[7] --> s31
	ldrb r6, [r3], #0x4				// r6 = state[11] --> s32
	ldrb r7, [r3]					// r7 = state[15] --> s33

	sub r3, #0xC
	strb r7,[r3], #0x4				// state[3] = state[15]
	strb r4,[r3], #0x4				// state[7] = state[3]
	strb r5,[r3], #0x4				// state[11] = state[7]
	strb r6,[r3]					// state[15] = state[11]

	sub r3, #0xF
	
	//////////////////////////////

	
	add r10, #0x1					// r3 = @state +1
	ldrb r4, [r10], #0x4			// r4 = state[1] --> s10
	ldrb r5, [r10], #0x4			// r5 = state[5] --> s11
	ldrb r6, [r10], #0x4			// r6 = state[9] --> s12
	ldrb r7, [r10]					// r7 = state[13] --> s13

	sub r10, #0xC					// come back to the fist byte @

	strb r5,[r10], #0x4				// state[1] = state[5]
	strb r6,[r10], #0x4				// state[5] = state[9]
	strb r7,[r10], #0x4				// state[9] = state[13]
	strb r4,[r10], #0x4				// state[13] = state[1]

	sub r10, #0xF
	ldrb r4, [r10], #0x4			// r4 = state[2] --> s20
	ldrb r5, [r10], #0x4			// r5 = state[6] --> s21
	ldrb r6, [r10], #0x4			// r6 = state[10] --> s22
	ldrb r7, [r10]					// r7 = state[12] --> s23

	sub r10, #0xC
	strb r6,[r10], #0x4				//state[2] = state[10] 
	strb r7,[r10], #0x4				//state[6] = state[12] 
	strb r4,[r10], #0x4				//state[10] = state[2] 
	strb r5,[r10]					//state[12] = state[6]

	sub r10, #0xB
	ldrb r4, [r10], #0x4			// r4 = state[3] --> s30	
	ldrb r5, [r10], #0x4			// r5 = state[7] --> s31
	ldrb r6, [r10], #0x4			// r6 = state[11] --> s32
	ldrb r7, [r10]					// r7 = state[15] --> s33

	sub r10, #0xC
	strb r7,[r10], #0x4				// state[3] = state[15]
	strb r4,[r10], #0x4				// state[7] = state[3]
	strb r5,[r10], #0x4				// state[11] = state[7]
	strb r6,[r10]					// state[15] = state[11]

	sub r10, #0xF
	bx LR
	
	
	
/************************************************************************
* MixColumns: It modifies only state
* r10 = @state
* r6 = @xtime
* r5 = @state2
* r4, r5, r6, r7, r8, r11, r12 = local variables
* Unused : r0, r1, r2, r9, r3
*/
	
MixColumns MYLABEL 				//r3 = @state ; r6 used in lnot used : r12
 
#if defined(__CC_ARM)       		// Keil
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 4      
count   SETA    count+1      
#elif defined (__GNUC__)    		// GCC
    .rept 4
#endif
	ldrb r8, [r10], #0x1			// r8 = a1
	
	ldrb r11, [r10], #0x1			// r11 = a2
	eor r4, r8, r11					// r4 = a1 xor a2

	ldrb r12, [r10], #0x1			// r12 = a3
	eor r4, r4, r12					// r4 = a1 xor a2 xor a3

	ldrb r5, [r10]					// r5 = a4
	eor r4, r4, r5					// r4 = a1 xor a2 xor a3 xor a4 = t
	sub r10, #0x3					// come back to the first byte adr

	eor r7, r8, r11					// r7 = a1+a2
	
	add  r7, r6						// r7 = @xtime[a1+a2]
	ldrb r7, [r7]					// r7 = xtime[a1+a2] = 2(a1+a2)

	eor r7, r8						// r7 = 2*(a1+a2)+a1
	eor r7, r4						// r7 = 2*(a1+a2)+a1+t
	strb r7, [r10], #0x1			// store in state

	eor r7, r11, r12				// r7 = a2+a3
	
	add  r7, r6						// r7 = @xtime[a2+a3]
	ldrb r7, [r7]					// r7 = xtime[a2+a3] = 2(a2+a3)
	eor r7, r11						// r7 = 2*(a2+a3)+a2
	eor r7, r4						// r7 = 2*(a2+a3)+a2+t
	strb r7, [r10], #0x1			// store in state	

	eor r7, r12, r5					// r7 = a3+a4
	
	add  r7, r6						// r7 = @xtime[a3+a4]
	ldrb r7, [r7]					// r7 = xtime[a3+a4] = 2(a3+a4)
	
	eor r7, r12						// r7 = 2*(a3+a4)+a3
	eor r7, r4						// r7 = 2*(a3+a4)+a3+t
	strb r7, [r10], #0x1

	eor r7, r8, r5					// r7 = a1+a4

	add  r7, r6						// r7 = @xtime[a1+a4]
	ldrb r7, [r7]					// r7 = xtime[a1+a4] = 2*(a1+a4)	
	
	eor r7, r5						// r7 = 2*(a1+a4)+a4
	eor r7, r4						// r7 = 2*(a1+a4)+a4+t
	strb r7, [r10], #0x1
	#if defined(__CC_ARM)       	// Keil
		WEND
	#elif defined (__GNUC__)    	// GCC
		.endr
	#endif			

	bx LR
	
	

/************************************************************************
* KeyExpansion (key schedule) : For each round, it generates a derivated key
* r2 = @rcon
* r6 = @key_state at index round number (contains 11 of 16 byte keys)
* r4, r5, r7, r8, r12 = local variables
* not used : r0, r1, r3, r9, r11
*/

KeyExpansion MYLABEL				// @r6 contains the i-th key ki = w0|w1|w2|w3
	movw r5, #:lower16:sbox			// r5 = @sbox
	movt r5, #:upper16:sbox
	
	//RotWord()
	add r6, #0xC					// r6 = @w3 
	ldr r8, [r6]					// r8 = w3 (last word of ki) = w3[3]|w3[2]|w3[1]|w3[0]
	ror r8, #0x8					// r8 = w3[0]|w3[3]|w3[2]|w3[1] (rotation right 8 bits) = temp
	add r12, r6, #0x4				// r12 = @key_state[round*16] @derivated key
	str r8,[r12]					// store r4 (four bytes of the derivated key) 

	// i is the ith key word generated 
	//SubWord()
	// unroll :loop_SubBytes_ke MYLABEL	// j position in key word temp j in {0, 1, 2, 3}	
	#if defined(__CC_ARM)       	// Keil
	
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 4      
count   SETA    count+1   
#elif defined (__GNUC__)    		// GCC
    .rept 4
#endif
   ldrb r8,[r12]					// r8 = temp[j] (last bytes derivated w stored in keystate[i*4])
   add r8, r5						// r8 = @sbox[temp[j]]
   ldrb r8, [r8]					// r8 = sbox[temp[j]]= temp[j]
   strb r8, [r12] , #01	 			// Store temp[j] in keystate[rnd*16*8+j*8]
#if defined(__CC_ARM)       		// Keil
	WEND
#elif defined (__GNUC__)    		// GCC
    .endr
#endif	
	
	//  BNE loop_SubBytes_ke
   sub r12, #0x4					// r12 = @temp current word key value 
   ldr r4, [r12]					// r4 = temp load current key word
   ldr r8, [r2], #0x4   			// r8 = load the four bytes of rcon_rnd : rcon_rnd is the rnd-th word of rcon  
   eor r4, r8						// r4 = temp xor rcon_rnd 
   //
   sub r8, r12, #0x10				// r8 = @w -16 (column i-4 adr)=@w0
   ldr r8, [r8]						// r8 = w0
   eor r4, r8						// r4 = w0 xor temp then temp = r4
   sub r7, r12, #0xc				// r7 = @w1 (thre column before)
   str r4, [r12],#0x4				// store r4 (temp) in r11 = @keystate [round* 16*8 * rnd]


	//Xor_Exp_Loop MYLABEL			// j = 1, 2, 3
   ldr r8, [r7], #0x4           	// r8 = wj ; r7 = @wj+1
   eor r4, r8						// r4 = temp xor wj then temp = r4
   str r4, [r12],#0x4				// store temp in @keystate [round* 16*8 * rnd + 8*j]

   //unroll
   ldr r8, [r7], #0x4           	// r8 = wj ; r7 = @wj+1
   eor r4, r8						// r4 = temp xor wj then temp = r4
   str r4, [r12], #0x4					// store temp in @keystate [round* 16*8 * rnd + 8*j]

   //unroll
   ldr r8, [r7], #0x4           	// r8 = wj ; r7 = @wj+1
   eor r4, r8						// r4 = temp xor wj then temp = r4
   str r4, [r12]					// store temp in @keystate [round* 16*8 * rnd + 8*j]

	bx LR
	


/************************************************************************
* Add_roundkey : Xor between state and the derivated key multiplied by the byte rmult
* 
* PREREQUISITE: the state bytes xi are already in the form G(xi)= rmult * xi xor rin
* r3 = @state
* r8 = @state_key 
* (r0, r1, r2 saved), r4, r5, r6, r7, r8, r10, r11 = local variables
*/
Add_roundkey MYLABEL				// r3 = @state ; 
	movw r7, #:lower16:key_mstate	// r7 = @key_mstate
    movt r7, #:upper16:key_mstate
				
	movw r12, #:lower16:GTab		// r12 = @Gtab
    movt r12, #:upper16:GTab


	#if defined(__CC_ARM)       	// Keil
	
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 16      
count   SETA    count+1   
#elif defined (__GNUC__)    		// GCC
    .rept 16
#endif
	ldrb r6, [r8], #0x1				// load the ith byte ki of key and inc #r8
	add r6, r6, r12         		// compute r6 <- # (G [ki]) 
	ldrb r6, [r6]           		// r6 <- G[ki]
	strb r6, [r7], #0x1	    		// store G[ki] in the ith cell of key-mstate and inc #r1
#if defined(__CC_ARM)       		// Keil
	WEND
#elif defined (__GNUC__)    		// GCC
    .endr
#endif	
	sub r7, #0x10		    	
	
	push {r0-r1}
	ldm r3, {r0, r1, r4, r12}		// r0 = state[0;3]; r1 = state[4;7] ; r4 =  state[8;11] ; r12 = state[12;15] ;
	ldm r7, {r5, r6, r8, r10}   	// r5 = mkey[0;3] ;r6 =mkey[4;7] ;r8 = mkey[8;11] ;r10 = mkey[12; 15];
	eor r0, r0, r5					// r0 = state[0;3] xor mkey[0;3]	
	eor r1, r1, r6					// r1 = state[4;7] xor mkey[4;7]
	eor r4, r4, r8					// r4 = state[8;11] xor mkey[8;11]
	eor r12, r12, r10				// r12 = state[12;15] xor mkey[12; 15]
	stm r3, {r0, r1, r4, r12}		// store value 
	
	pop {r0-r1}

	bx LR
	
	
	
/************************************************************************
* AES :
* r0 = @message in the first place then global variable for round number
* r1 = @key in the first place then current derivated key @
* r2 = @Random (19 byte table, byte rin0,byte rin1, byte Rout)
* r3 = @result in the first place then global variable for @rcon
* r4, r5, r6, r7, r8, r10, r12 = local variables
* Do not use r9 and r11
* random bytes in random variable has to be instanciated before aes() call.
* Important : random is not generated by the followinf function and rmult !=0 (random[18]) otherwise error 
* For GoodUSB project, this is managed in the main.c 
*/

anssi_aes_masked MYLABEL
	push.w {LR}
	push.w {r0-r2}  			
	push.w {r4-r12}
	push {r3}						// push @result
	
	bl.w Load_data
		
	bl.w Compute_GTab
	 
    push {r1}						// push @key
	
    bl.w Compute_Affine_sboxMasked	// Computation of the masked Sbox 

    // Multiplication
    movw r3, #:lower16:state		// r3 = @state 
    movt r3, #:upper16:state	
   
#if defined(__CC_ARM)       		// Keil
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 16     
count   SETA    count+1      
#elif defined (__GNUC__)    		// GCC
    .rept 16
#endif
    ldrb r6, [r3] 					// r6 = state[i] is a byte 
   	add r4, r6, r12					// r4 = @Gtab[state[i]]
	ldrb r6, [r4]					// r6 = Gtab[state[i]]
    strb r6, [r3], #0x1				// store r6 in @state[i]	
#if defined(__CC_ARM)       		// Keil
	WEND
#elif defined (__GNUC__)    		// GCC
    .endr
#endif	
   
    // State masking				        		
    movw r3, #:lower16:state		// r3 = @state 
    movt r3, #:upper16:state	
			
	movw r7, #:lower16:state2		// r7 = @state2
    movt r7, #:upper16:state2	
	
	// Xor_State2					// State[i] = State[i]*rmult xor state2[i]
	ldm r3, {r0, r1, r4, r12}
	ldm r7, {r5, r6, r8, r10}
	eor r0, r0, r5
	eor r1, r1, r6
	eor r4, r4, r8
	eor r12, r12, r10
	stm r3, {r0, r1, r4, r12}
	
	pop {r8}							// retrieve @key : r8 = @key
	
	// Load key in key_state
	movw r1, #:lower16:key_state		// r1 = @state2
    movt r1, #:upper16:key_state	
	
	ldm r8, {r5, r6, r10, r12}			// load key in key_state[0;15]
	stm r1, {r5, r6, r10, r12}
		
	//AddRoundKey
	bl.w Add_roundkey			// state[i] = state[i] xor rmult* key_state[i]

	mov r0, #0xA				// r0 = 10 (round ctr)	
			
	movw r2, #:lower16:rcon		// r2 = @rcon
	movt r2, #:upper16:rcon
	
//////////////////////////////////////BEGIN ROUND/////////////////////////////////////////////////////////////////
Round_Loop MYLABEL				// Rounds Loop
			
	movw r7, #:lower16:rin		// r7 = @rin
	movt r7, #:upper16:rin
	// Xor_word					// state[i] = state[i] xor rin
	ldr r5, [r7]				//r5 = wordB
#if defined(__CC_ARM)       	// Keil
count   SETA    1    			// set the arithmetic value count to 1        
    WHILE   count <= 4    
count   SETA    count+1      
#elif defined (__GNUC__)    	// GCC
    .rept 4
#endif

	ldr  r6, [r3]				// r6 = state[count; count + 3]
	eor  r6, r5					// r6 = state[count; count + 3] xor WordB
	str  r6, [r3], #0x4			// save r6 in @state[count; count + 3] and go to the next state word
	
#if defined(__CC_ARM)       	// Keil
	WEND
#elif defined (__GNUC__)    	// GCC
	.endr
#endif
	sub r3, #0x10				// come back to the beginning of state
	
	bl.w SubBytesWithMask 		// state[i] = SB(state[i]) xor Rout

	sub r3, #0x10				// come back to the beginning of state
	
	bl.w ShiftRowsWithMasked 	// state[i]= SR(state[i]) xor SR(state2[i])

	cmp r0, #0x1				// The last round do not process MixColumns
	
	beq.w No_Mix
	
	//MixColumns_masked 		//  MixColumns(state2) and  MixColumns(state)
	movw r6, #:lower16:xtime	// Store in r6 the @ of xtime table ( multiplication by 2)	
	movt r6, #:upper16:xtime
	
	bl MixColumns				// MixColumns(state2)
	
	mov r10, r3
	
	bl MixColumns				// MixColumns(state)

		
No_Mix MYLABEL
	mov r6, r1					// r6 = @key_state[rnd*16*8] 			
	
	bl.w KeyExpansion			// Generation of the next subkey

	add r1, #0x10				// r1 = @key_state[rnd*16*8] +16*8 =@key_state[(rnd+1)*16*8] Go to the next @key in key state
	
	mov r8,r1					// r8 = @key_state[(rnd+1)*16*8] 
	
	bl.w Add_roundkey 			// state[i] = state[i] xor k_j[i]

	
	subs r0, #0x1
	bne Round_Loop					// End of round loop
	/////////////////////////////////END ROUND/////////////////////////////////////////////////////////////////////////////////////////////////		
	
	movw r7, #:lower16:state2 		// r7 = @state2
	movt r7, #:upper16:state2
	
	//Xor State2					// remove mask for the last round : state[i] = y[i] xor z[i]	
	ldm r3, {r0, r1, r4, r12}
	ldm r7, {r5, r6, r8, r10}
	eor r0, r0, r5
	eor r1, r1, r6
	eor r4, r4, r8
	eor r12, r12, r10
	stm r3, {r0, r1, r4, r12}
		
    movw r0, #:lower16:LogTable		// r0 = @LogTable
	movt r0, #:upper16:LogTable
   		
    movw r1, #:lower16:ALogTable	// r1 = @ALogTable
	movt r1, #:upper16:ALogTable
				
    movw r4, #:lower16:rmult		// r4 = @rmult	
	movt r4, #:upper16:rmult
   
   
    ldrb r2, [r4]					// r2 = rmult = z^a
    add r4, r0, r2					// r4 = @LogTable[table z^a]  ; index pour lire dans alog
    ldrb r2, [r4]					// r2 = a
    mov r12, #0xFF					// r12 = 255
    sub r2, r12,r2					// r2 = 255 - a  
   
    mov r7, r3						// r7 = @state
 
   
   // Unroll : Inverse_Loop MYLABEL	// for j = 0 to j = 15
 
   #if defined(__CC_ARM)       		// Keil
count   SETA    1    				// set the arithmetic value count to 1        
    WHILE   count <= 16 
count   SETA    count+1      
#elif defined (__GNUC__)    		// GCC
    .rept 16
#endif

   ldrb r11, [r7]		   			// r11 = state[j] = z^b
   add r10, r11, r0		   			// r10 = @LogTable[state[j]] 
   ldrb r10, [r10]		   			// r10 = LogTable[state[j]] = b  
   add  r10, r10, r2		   		// r10 = b - a 
   lsr  r4, r10, #8        			// r4 = 1 if r5>255 and 0 otherwise; r11 = carry  
   add  r10, r4            			// r10 = b - a + carry  
   and  r10,r10,r12          		// r10 = b - a mod (255)
   add r10, r1  			   		// r10 = @Alog[b - a mod (255)]
   ldrb r6,[r10]			   		// r6 = Alog[b - a mod (255)]	
  
// we suppose that rmult !=0
   
   cmp r11, #0x0					// >254

   it gt
   movgt r10, #0xFF

   it eq
   moveq r6, #0x0
   
   it lt
   movlt r10, #0x00
   strb r6, [r7], #0x1				// store dans state

#if defined(__CC_ARM)       		// Keil
	WEND
#elif defined (__GNUC__)    		// GCC
    .endr
#endif	
    	
   pop {r7}							// push @result
   
   ldm r3, {r5, r6, r10, r8}		// save state value in @result
   stm r7, {r5, r6, r10, r8}
   
  
	pop {r4-r12}		// Restore Registers R4-R11 from the stack
	pop {r0-r2}
	pop {PC}
   //POP.W   {R0-R12,PC}      	
   END 
	   
	   
		
