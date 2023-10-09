#ifndef EK_H
#define EK_H

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>

TPM_RC StoreEmptyEkNonceInNvIndex(void);
TPM_RC StoreSigningEkTemplateInNvIndex(void);
TPM_RC StoreEkCertificateInNvIndex(void);
TPM_RC GetEkTemplate(TPMT_PUBLIC *publicArea);
TPM_RC GetSigningEkTemplate(TPMT_PUBLIC *publicArea);

#endif /* EK_H */
