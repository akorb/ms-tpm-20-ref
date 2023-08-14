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

TPM_RC
Generate_Ek_Pub(char *buffer, size_t *len)
{
    TPM_RC result;
    int in_len = *len;

    const char authPolicyValue[] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
                                    0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                                    0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
                                    0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                                    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
                                    0x69, 0xAA};

    TPMT_PUBLIC publicArea;
    TPMT_SENSITIVE sensitive;
    DRBG_STATE rand;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_NAME name;
    memset(&publicArea, 0, sizeof(publicArea));
    memset(&sensitive, 0, sizeof(sensitive));
    memset(&rand, 0, sizeof(rand));
    memset(&inSensitive, 0, sizeof(inSensitive));

    // These are the values for the default RSA template as defined by the TPM EK Profile spec in Appendix B
    publicArea.type = TPM_ALG_RSA;
    publicArea.nameAlg = TPM_ALG_SHA256;
    publicArea.objectAttributes = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt;
    publicArea.authPolicy.t.size = 32;
    memcpy(publicArea.authPolicy.t.buffer, authPolicyValue, sizeof(authPolicyValue));
    publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    publicArea.parameters.symDetail.sym.keyBits.aes = 128;
    publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
    publicArea.parameters.asymDetail.scheme.scheme = TPM_ALG_NULL;                 // Details already set to NULL
    publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg = TPM_ALG_NULL; // Details already set to NULL
    publicArea.parameters.rsaDetail.keyBits = 2048;
    publicArea.parameters.rsaDetail.exponent = 0;
    publicArea.unique.rsa.t.size = 256; // Buffer is already set to 0

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

    /*
    CreatePrimary_In in;
    // This also sets the sensitive data to zero, just as required by the spec
    memset(&in, 0, sizeof(in));

    in.primaryHandle = TPM_RH_ENDORSEMENT;

    in.inPublic.publicArea.type = TPM_ALG_RSA;
    in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    in.inPublic.publicArea.objectAttributes = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt;
    in.inPublic.publicArea.authPolicy.t.size = 32;
    memcpy(in.inPublic.publicArea.authPolicy.t.buffer, authPolicyValue, sizeof(authPolicyValue));
    in.inPublic.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    in.inPublic.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
    in.inPublic.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
    in.inPublic.publicArea.parameters.asymDetail.scheme.scheme = TPM_ALG_NULL;                 // Details already set to NULL
    in.inPublic.publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg = TPM_ALG_NULL; // Details already set to NULL
    in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    in.inPublic.publicArea.unique.rsa.t.size = 256; // Buffer is already set to 0

    CreatePrimary_Out out;
    memset(&out, 0, sizeof(out));

    DMSG("Execute TPM2_CreatePrimary");
    result = TPM2_CreatePrimary(&in, &out);

    DMSG("Result of TPM2_CreatePrimary: 0x%x", result);

    if (result == TPM_RC_SUCCESS)
    {
        DMSG("Public key size: %d", out.outPublic.publicArea.unique.rsa.t.size);
        DMSG("Public key start: %x %x %x %x", out.outPublic.publicArea.unique.rsa.t.buffer[0], out.outPublic.publicArea.unique.rsa.t.buffer[1], out.outPublic.publicArea.unique.rsa.t.buffer[2], out.outPublic.publicArea.unique.rsa.t.buffer[3]);
        DMSG("Public key followup: %x %x %x %x", out.outPublic.publicArea.unique.rsa.t.buffer[4], out.outPublic.publicArea.unique.rsa.t.buffer[5], out.outPublic.publicArea.unique.rsa.t.buffer[6], out.outPublic.publicArea.unique.rsa.t.buffer[7]);
    }

    return TPM_RC_SUCCESS;
    */
}
