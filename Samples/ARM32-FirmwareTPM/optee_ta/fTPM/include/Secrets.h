#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>


/*************** SHORT TERM SECRETS *************************/

/**
 * According to [1], "the DICE creates this CDI using a one-way function with at least the same security strength as the attestation process."
 * Our FWIDs are SHA256 values. So, the CDI should be 256 bits (= 32 bytes) as well.
 * 
 * [1] Hardware Requirements for a Device Identifier Composition Engine
 */
extern uint8_t CDI[32];

/**
 * You might have expected that the storage key is a long term secret.
 * However, we create a TEE_Operation which copies the key to kernel space of the OP-TEE OS, so we can treat it as a short term key
 * and just use the according operation.
 */
extern uint8_t storage_key[16];

// TODO: Maybe replace constant 64 with a definition provided by TPM, e.g., PRIMARY_SEED_SIZE
extern uint8_t EPS[64];


/*************** LONG TERM SECRETS *************************/

extern TPMT_SENSITIVE EkSigningPrivKey;

/**
 * Example code of how to extract the actual RSA public key
 * memcpy(buffer, publicArea.unique.rsa.t.buffer, publicArea.unique.rsa.t.size);
 */
extern TPMT_PUBLIC EkSigningPubKey;  // This is not a secret, but only fits here as well.


void destroyShortlivingSecrets(void);
void destroyAllSecrets(void);
void initEPS(void);
void initStorageKey(void);
void initEkKeys(void);
void destroyAllSecrets(void);


#endif /* SECRETS_H */
