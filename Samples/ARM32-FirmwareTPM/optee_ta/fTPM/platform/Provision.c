#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>


TPM_RC ProvisionWithStaticData()
{
    TPM_RC result = TPM_RC_SUCCESS;

    result = StoreSigningEkTemplateInNvIndex();

    if (result == TPM_RC_SUCCESS)
        result = StoreEmptyEkNonceInNvIndex();

    return result;
}

/**
 * This provisions the fTPM with data that may change on each boot.
 * For example, because it depends on the result of the attestation.
 */
TPM_RC ProvisionWithDynamicData()
{
    TPM_RC result = TPM_RC_SUCCESS;

    result = StoreEkCertificateInNvIndex();

    return result;
}
