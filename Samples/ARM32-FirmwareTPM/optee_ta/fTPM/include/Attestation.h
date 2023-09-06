#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdint.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>

// The certificates are stored here in DER format
// For our certificates, they are always a bit smaller than 1000 bytes.
// We expect a certificate chain of length 5.
// So, give a 5 * 1000 bytes buffer
extern uint8_t buffer_crts[5000];

// first element is length of chain
// Array size must be at least length of chain + 1
extern uint16_t buffer_sizes[8];


TPM_RC sign_nonce(const char *nonce, const size_t nonceSize, char *outputBuf, size_t *outputBufSize);
TEE_Result do_attestation(void);

#endif /* ATTESTATION_H */
