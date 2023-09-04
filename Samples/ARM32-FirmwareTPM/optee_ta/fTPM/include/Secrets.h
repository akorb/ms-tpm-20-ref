#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

/*
According to [1], "the DICE creates this CDI using a one-way function with at least the same security strength as the
attestation process."

Our TCIs are SHA256 values. So, the CDI should be 256 bits (= 32 bytes) as well.

[1] Hardware Requirements for a Device Identifier Composition Engine
*/
extern uint8_t CDI[32];

extern uint8_t storage_key[16];

// TODO: Maybe replace constant 64 with a definition provided by TPM, e.g., PRIMARY_SEED_SIZE
extern uint8_t EPS[64];


void destroySecrets();
void initSecrets();


#endif /* SECRETS_H */
