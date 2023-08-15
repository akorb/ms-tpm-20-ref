#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>
#include <CreatePrimary_fp.h>
#include <NV_Read_fp.h>

// From TPM EK Profile spec
#define EK_RSA_NONCE_NV_INDEX 0x01c00003
#define EK_RSA_TEMPLATE_NV_INDEX 0x01c00004


static TPM_RC
Get_Ek_Nonce_From_NV(char *buffer, size_t *bufferLen)
{
    NV_Read_In      nv_in;
    NV_Read_Out     nv_out;

    memset(&nv_out, 0, sizeof(nv_out));

    NV_REF           locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(EK_RSA_NONCE_NV_INDEX, &locator);

    // It's null if the NV index is not populated
    if (nvIndex == NULL)
        return TPM_RC_NV_UNAVAILABLE;
    
    int nonceSize = nvIndex->publicArea.dataSize;
    if (nonceSize > *bufferLen)
    {
        EMSG("Get_Ek_Nonce: bufferLen (0x%02x) is too short. Required: 0x%02x", bufferLen, nonceSize);
        return TPM_RC_MEMORY;
    }

    // Disclaimer: The following code is untested since
    // I didn't have an fTPM which includes an EK template

    nv_in.nvIndex = EK_RSA_NONCE_NV_INDEX;
    nv_in.authHandle = TPM_RH_OWNER;
    nv_in.size = nonceSize;
    nv_in.offset = 0;

    TPM_RC result = TPM2_NV_Read(&nv_in, &nv_out);
    if (result != TPM_RC_SUCCESS)
        return result;
    
    *bufferLen = nv_out.data.t.size;

    memcpy(buffer, nv_out.data.t.buffer, nv_out.data.t.size);
    return TPM_RC_SUCCESS;
}

static TPM_RC
Get_Ek_Template_From_NV(TPMT_PUBLIC *publicArea)
{
    NV_Read_In      nv_in;
    NV_Read_Out     nv_out;

    memset(&nv_out, 0, sizeof(nv_out));

    NV_REF           locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(EK_RSA_TEMPLATE_NV_INDEX, &locator);

    // It's null if the NV index is not populated
    if (nvIndex == NULL)
        return TPM_RC_NV_UNAVAILABLE;

    // Disclaimer: The following code is untested since
    // I didn't have an fTPM which includes an EK template

    if (nvIndex->publicArea.dataSize != sizeof(*publicArea))
    {
        EMSG("Unexpected EK template size. Couldn't test it unfortunately.");
        return TPM_RC_FAILURE;
    }

    nv_in.nvIndex = EK_RSA_TEMPLATE_NV_INDEX;
    nv_in.authHandle = TPM_RH_OWNER;
    nv_in.size = sizeof(*publicArea);
    nv_in.offset = 0;

    TPM_RC result = TPM2_NV_Read(&nv_in, &nv_out);
    if (result != TPM_RC_SUCCESS)
        return result;

    memcpy(publicArea, nv_out.data.t.buffer, nv_out.data.t.size);
    return TPM_RC_SUCCESS;
}

TPM_RC
Get_Ek_Template(TPMT_PUBLIC *publicArea)
{
    // As defined in the TPM EK Profile spec
    const char authPolicyValue[] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
                                    0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                                    0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
                                    0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                                    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
                                    0x69, 0xAA};

    // The nonce is as big as the cryptosystem.
    // We rely on RSA 2048, which is 256 bytes.
    // To be more future proof, we still use the preprocessor constant MAX_RSA_KEY_BYTES
    // which is set according to count of bytes of the "biggets" cryptosystem supported by the TPM.
    // In fact, at time of writing, MAX_RSA_KEY_BYTES resolves indeed to 256.
    // You'll still find some '256' constants in the code below, but with this comment
    // I hope you get the idea how it's easier to make the attestation system more agile.
    char nonce[MAX_RSA_KEY_BYTES];
    size_t nonceSize = sizeof(nonce);

    int ekTemplateRetrieved = Get_Ek_Template_From_NV(publicArea) == TPM_RC_SUCCESS;
    int ekNonceRetrieved = Get_Ek_Nonce_From_NV(nonce, &nonceSize) == TPM_RC_SUCCESS;

    /*
    The TPM spec allows manufacturers to supply a proprietary EK template at a NV index 0x01c00004.
    So, check this one first, and use the default template as a fallback.
    */
    if (ekTemplateRetrieved)
    {
        // Uncommon path (in my experience)

        if (ekNonceRetrieved)
        {
            /* [Spec]
            If the EK Template is Populated and the EK Nonce is Populated, form the TPMT_PUBLIC as follows:
            1. Begin with the EK Template.
            2. Add the EK Nonce to the default template as follows:
                • For RSA 2048, the EK Nonce is padded to 256 bytes by appending 0x00 bytes.
                This value is inserted into the default template unique.rsa.t.buffer, and
                unique.rsa.t.size is set to 256.
            */

            // We already initialized the whole nonce array with 0x00 bytes.
            // So, we just don't do anything.

            // DISCLAIMER: Untested. Maybe the 0x00 bytes need to be appened at the other side of the buffer.
            memcpy(publicArea->unique.rsa.t.buffer, nonce, sizeof(nonce));
            publicArea->unique.rsa.t.size = 256;
        }
        else
        {
            /* [Spec]
            If the EK Template is Populated and the EK Nonce is Absent,
            the EK Template is used unmodified as the TPMT_PUBLIC.
            */
        }
    }
    else
    {
        if (ekNonceRetrieved)
        {
            /* [SPEC]
            The case of an EK Template Absent and an EK Nonce Populated is unspecified
            and MUST NOT be provisioned.
            */
           return TPM_RC_FAILURE;
        }
        else
        {
            // Most common path
            // Also taken when the fTPM code is used without any configurations

            // [Spec] If the EK Template is Absent, the default template is used as the TPMT_PUBLIC

            // These are the values for the default RSA template as defined by the TPM EK Profile spec in Appendix B
            publicArea->type = TPM_ALG_RSA;
            publicArea->nameAlg = TPM_ALG_SHA256;
            publicArea->objectAttributes = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt;
            publicArea->authPolicy.t.size = 32;
            memcpy(publicArea->authPolicy.t.buffer, authPolicyValue, sizeof(authPolicyValue));
            publicArea->parameters.symDetail.sym.algorithm = TPM_ALG_AES;
            publicArea->parameters.symDetail.sym.keyBits.aes = 128;
            publicArea->parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
            publicArea->parameters.asymDetail.scheme.scheme = TPM_ALG_NULL;
            publicArea->parameters.asymDetail.scheme.details.anySig.hashAlg = TPM_ALG_NULL;
            publicArea->parameters.rsaDetail.keyBits = 2048;
            publicArea->parameters.rsaDetail.exponent = 0;
            publicArea->unique.rsa.t.size = 256;
        }
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
Generate_Ek_Pub(char *buffer, size_t *len)
{
    TPM_RC result;
    int in_len = *len;

    TPMT_PUBLIC publicArea;
    TPMT_SENSITIVE sensitive;
    DRBG_STATE rand;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_NAME name;
    memset(&publicArea, 0, sizeof(publicArea));
    memset(&sensitive, 0, sizeof(sensitive));
    memset(&rand, 0, sizeof(rand));
    memset(&inSensitive, 0, sizeof(inSensitive));
    memset(&name, 0, sizeof(name));

    result = Get_Ek_Template(&publicArea);
    if (result != TPM_RC_SUCCESS)
        return result;

    // The following code is copied and adapted from the `TPM2_CreatePrimary` function.
    // The `TPM2_CreatePrimary` function creates a transient object to store the key in,
    // we don't want that. We really only want to get a buffer with the key, that's all. No side-effects.
    result = DRBG_InstantiateSeeded(&rand,
                                    &HierarchyGetPrimarySeed(TPM_RH_ENDORSEMENT)->b,
                                    PRIMARY_OBJECT_CREATION,
                                    (TPM2B *)PublicMarshalAndComputeName(&publicArea, &name),
                                    &inSensitive.sensitive.data.b);
    if (result != TPM_RC_SUCCESS)
    {
        EMSG("DRBG_InstantiateSeeded failed with 0x%x", result);
        return result;
    }

    result = CryptRsaGenerateKey(&publicArea, &sensitive, &rand);
    if (result != TPM_RC_SUCCESS)
    {
        EMSG("CryptRsaGenerateKey failed with 0x%x", result);
        return result;
    }

    IMSG("Public key size: %d", publicArea.unique.rsa.t.size);
    IMSG("Public key start: %x %x %x %x ...", publicArea.unique.rsa.t.buffer[0], publicArea.unique.rsa.t.buffer[1], publicArea.unique.rsa.t.buffer[2], publicArea.unique.rsa.t.buffer[3]);

    if (in_len < publicArea.unique.rsa.t.size)
    {
        EMSG("Provided too short buffer. Expected: %d, Got: %d", publicArea.unique.rsa.t.size, len);
        return TPM_RC_MEMORY;
    }

    memcpy(buffer, publicArea.unique.rsa.t.buffer, publicArea.unique.rsa.t.size);
    *len = publicArea.unique.rsa.t.size;

    return result;
}
