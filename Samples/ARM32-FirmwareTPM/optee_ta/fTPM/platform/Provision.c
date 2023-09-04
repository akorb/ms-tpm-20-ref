#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>


TPM_RC Provision(int isFirstBoot)
{
    // Unconditionally update the EPS
    // If the system state did not change, it will be the same EPS, and the content is overwritten with the same content.
    // Otherwise, the EPS will have a new value, yielding a new EK invalidating each previously generated EKcert.
    updateEPS();

    TPM_RC result = TPM_RC_SUCCESS;
    
    if (isFirstBoot)
    {
        // TODO: Store EKcert in NV Index
        result = StoreSigningEkTemplateInNvIndex();

        if (result == TPM_RC_SUCCESS)
            result = StoreEmptyEkNonceInNvIndex();
    }

    return result;
}
