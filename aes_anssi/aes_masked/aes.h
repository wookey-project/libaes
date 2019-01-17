
#ifndef _AES_H_
#define _AES_H_

#include "affine_aes.h"

#define LENGTH_BLOCK 16
#define LENGTH_KEY   16
#define LENGTH_COUNT  4

/*
 * \struct STRUCT_AES
 * \brief
 */
typedef struct
{
	STRUCT_KEY_CONTEXT key_context;
	STRUCT_AES128_CONTEXT aes_context;
	UINT  ctr_aes;														// number of encryption/decryption under the same aes ramdom
	UINT  ctr_key;														// number of encryption/decryption under the same key ramdom
	UCHAR state;														  // state of the initialisations (aes and key contexts)
	UCHAR t_random [2*19];
}  STRUCT_AES;

/*
Different modes: the mode is the command send to the aes function
Mode = b(MODE_DEC)||b(MODE_ENC)|b(MODE_AESINIT)|b(MODE_KEYINI0T)
*/

/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */

enum MODE_TYPE{
	MODE_UNSPECIFIED 	= 0x0000,
	MODE_KEYINIT 	   	= 0x0001, // Key context initialization command (fresh random value)
	MODE_AESINIT_ENC 	= 0x0002, // AES context initialisation command for encryption (fresh random value)
	MODE_AESINIT_DEC 	= 0x0004, // AES context initialisation command for decryption (fresh random value)
	MODE_ENC 		= 0x0008,       // Encryption command
	MODE_DEC 		= 0x0010,       // Decryption command
	MODE_RANDOM_KEY_EXT = 0x20, // When Randomness for the key scheduling is provided by the user
	MODE_RANDOM_AES_EXT = 0x40  // When Randomness for the aes processing is provided by the user
};


/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */
enum STATE_TYPE{
	STATE_INITIALIZED 		= 0x0000,	// Initialized state (key context uninitialized and aes context uninitialized)
	STATE_KEYINIT		        = 0x0001,	// Masked key schedule done
	STATE_AESINIT_ENC	        = 0x0002, 	// AES context initialized (LOK for encryption)
	STATE_AESINIT_DEC		= 0x0004	// LOK: AES context initialized for decryption
};

/* Mode
Error handling inconsistencies between in Mode command
*/
/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */

enum ERR_MODE
{
	ERR_NO_OPERATION 	= 0x1,	// The command is empty
	ERR_ENC_AND_DEC 	= 0x2, 	// The command ask for an encryption and decryption at the same time
	ERR_ENC_AND_DEC_AESINIT = 0x4,	// The command ask to initialize an encryption and decryption context at the same time
	ERR_AESINIT_AND_OP = 0x8  		// The command ask for an AESINIT_(OP) incompatible with operation (OP)= (ENC) or (DEC).
};



/* Operations
Errors handling inconsistencies between State and Mode
*/

/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */
enum ERR_OPERATION {
	ERR_OP_GEN_RANDOM_KEY	= 0x10,			// Error on key random generation
	ERR_OP_GEN_RANDOM_AES	= 0x20, 		// Error on aes random generation
	ERR_OP_KEYINIT		= 0x40, 		// Error when loading key
	ERR_OP_AESINIT		= 0x80,			// Error when initialization aes context (enc or dec) (LOK: a splitter ?)
	ERR_OP_ENC 		= 0x100,		// Error when doing encryption
	ERR_OP_DEC		= 0x200			// Error when doing decryption
	};


/* Parameters
Errors handling parameters inconsistencies
*/
// Possibilité de l'améliorer et de renvoyer une erreur du type KEY/INPUT_UNUSED

/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */
enum ERR_INPUT{
	ERR_SIZE_KEY		        = 0x0400,		// Key size inconsistent
	ERR_SIZE_INPUT		      = 0x0800,		// Input size inconsistent
	ERR_SIZE_OUTPUT		      = 0x1000,		// Output size inconsistent
	ERR_KEY_UNUSED 		      = 0x2000,		// A key is given as a parameter but will not be used in the asked MODE
	ERR_INPUT_UNUSED	      = 0x4000,		// An input is given as a parameter but will not be used in the asked MODE
	ERR_KEY_MISSING		      = 0x8000,		// The mode asked necessitate a key as a parameter but not given
	ERR_INPUT_MISSING	      = 0x1000,		// The input asked necessitate an input as a parameter but not given
	ERR_RANDOM_KEY_MISSING	= 0x0200,		// The random_key array is missing while in mode RANDOM KEY EXTERNAL
	ERR_RANDOM_AES_MISSING	= 0x0100		// The random_aes array is missing while in mode RANDOM AES EXTERNAL

};

/**
 * \enum MODE_TYPE
 * \brief Constantes d'erreurs.
 *
 * TODO 
 * 
 */
enum ERR_MODE_STATE{	// STATE et MODE command are inconsistent 
	ERR_AESINIT_MISSING	= 0x20000,		// AES context is missing (LOK: two enc and dec ?)
	ERR_KEYINIT_MISSING	= 0x40000,		// Key context is missing
	ERR_AESINIT_BAD		= 0x80000		// AES context initialized for ENC and ask for decryption and the opposite
};

#define ERR_UNKNOWN 		0x100000
#define NO_ERROR 		0x000000


UINT aes(UCHAR Mode, STRUCT_AES* struct_aes, const UCHARp key, const UCHARp input, UCHARp output, const UCHARp random_key, const UCHARp random_aes);
UINT test_mode(UCHAR Mode);
UINT test_mode_state(UCHAR Mode, UCHAR State);
UINT test_parameter_content(UCHAR Mode, const UCHARp key,  const UCHARp input, UCHARp output, const UCHARp random_aes, const UCHARp random_key);

#endif
