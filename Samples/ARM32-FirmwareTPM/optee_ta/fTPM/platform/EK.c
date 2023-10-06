#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>

#include <string.h>
#include <CreatePrimary_fp.h>
#include <NV_Read_fp.h>
#include <NV_DefineSpace_fp.h>
#include <NV_Write_fp.h>
#include <Marshal_fp.h>

#include "EK.h"
#include "Attestation.h"

// From TPM EK Profile spec
#define EK_RSA_CERTIFICATE_NV_INDEX 0x01c00002
#define EK_RSA_NONCE_NV_INDEX 0x01c00003
#define EK_RSA_TEMPLATE_NV_INDEX 0x01c00004


static TPM_RC
GetEkNonceFromNV(char *buffer, size_t *bufferLen)
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
GetEkTemplateFromNV(TPMT_PUBLIC *publicArea)
{
    NV_Read_In      nv_in;
    NV_Read_Out     nv_out;
    NV_REF          locator;
    TPM_RC          result;

    memset(&nv_out, 0, sizeof(nv_out));

    NV_INDEX *nvIndex = NvGetIndexInfo(EK_RSA_TEMPLATE_NV_INDEX, &locator);

    // It's null if the NV index is not populated
    if (nvIndex == NULL)
        return TPM_RC_NV_UNAVAILABLE;

    nv_in.nvIndex = EK_RSA_TEMPLATE_NV_INDEX;
    nv_in.authHandle = TPM_RH_OWNER;
    nv_in.size = nvIndex->publicArea.dataSize;
    nv_in.offset = 0;

    result = TPM2_NV_Read(&nv_in, &nv_out);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("TPM2_NV_Read failed with 0x%02x", result);
        return result;

    }

    INT32 size = (INT32)nv_out.data.t.size;
    BYTE *buffer = nv_out.data.t.buffer;
    result = TPMT_PUBLIC_Unmarshal(publicArea, &buffer, &size, 0);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("TPMT_PUBLIC_Unmarshal failed with 0x%02x", result);
        return result;
    }

    return TPM_RC_SUCCESS;
}

static TPM_RC
GetDefaultEkTemplate(TPMT_PUBLIC *publicArea)
{
    // As defined in the TPM EK Profile spec
    const char authPolicyValue[] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
                                    0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                                    0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
                                    0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                                    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
                                    0x69, 0xAA};

    memset(publicArea, 0, sizeof(*publicArea));

    // These are the values for the default RSA template as defined by the TPM EK Profile spec in Appendix B
    publicArea->type = TPM_ALG_RSA;
    publicArea->nameAlg = TPM_ALG_SHA256;
    publicArea->objectAttributes = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy | TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt;
    publicArea->authPolicy.t.size = 32;
    memcpy(publicArea->authPolicy.t.buffer, authPolicyValue, sizeof(authPolicyValue));

    publicArea->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    publicArea->parameters.rsaDetail.symmetric.keyBits.aes = 128;
    publicArea->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    publicArea->parameters.rsaDetail.keyBits = 2048;
    publicArea->parameters.rsaDetail.exponent = 0;

    publicArea->unique.rsa.t.size = 256;
    return TPM_RC_SUCCESS;
}

static TPM_RC
GetSigningEkTemplate(TPMT_PUBLIC *publicArea)
{
    // Start with default EK template
    TPM_RC result = GetDefaultEkTemplate(publicArea);
    
    if (result == TPM_RC_SUCCESS)
    {
        // Overrides
        publicArea->objectAttributes = TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent | TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy | TPMA_OBJECT_sign | TPMA_OBJECT_restricted;
        publicArea->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        publicArea->parameters.rsaDetail.symmetric.keyBits.aes = 0;
        publicArea->parameters.rsaDetail.symmetric.mode.aes = 0;
        publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
        publicArea->parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    }

    return result;
}

TPM_RC
GetEkTemplate(TPMT_PUBLIC *publicArea)
{
    // The nonce is as big as the cryptosystem.
    // We rely on RSA 2048, which is 256 bytes.
    // To be more future proof, we still use the preprocessor constant MAX_RSA_KEY_BYTES
    // which is set according to count of bytes of the "biggets" cryptosystem supported by the TPM.
    // In fact, at time of writing, MAX_RSA_KEY_BYTES resolves indeed to 256.
    // You'll still find some '256' constants in the code below, but with this comment
    // I hope the idea is helpful to make the attestation system more agile.
    char nonce[MAX_RSA_KEY_BYTES];
    size_t nonceSize = sizeof(nonce);

    TPM_RC result = TPM_RC_FAILURE;

    memset(publicArea, 0, sizeof(*publicArea));

    int ekTemplateRetrieved = GetEkTemplateFromNV(publicArea) == TPM_RC_SUCCESS;
    int ekNonceRetrieved = GetEkNonceFromNV(nonce, &nonceSize) == TPM_RC_SUCCESS;

    /*
    The TPM spec allows manufacturers to supply a proprietary EK template at a NV index 0x01c00004.
    So, check this one first, and use the default template as a fallback.
    */
    if (ekTemplateRetrieved)
    {
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

            // We already initialized publicArea->unique.rsa.t.buffer with 0x00 bytes.
            // So, we just set the nonce from NV and are done.

            memcpy(publicArea->unique.rsa.t.buffer, nonce, nonceSize);
            publicArea->unique.rsa.t.size = 256;
            result = TPM_RC_SUCCESS;
        }
        else
        {
            /* [Spec]
            If the EK Template is Populated and the EK Nonce is Absent,
            the EK Template is used unmodified as the TPMT_PUBLIC.
            */
            result = TPM_RC_SUCCESS;
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
           result = TPM_RC_FAILURE;
        }
        else
        {
            // [Spec] If the EK Template is Absent, the default template is used as the TPMT_PUBLIC
            result = GetDefaultEkTemplate(publicArea);
        }
    }

    return result;
}

static TPM_RC
DefineAndStoreInNVIndex(TPMI_RH_NV_AUTH hierarchy, TPMA_NV attributes, TPMI_RH_NV_INDEX nvIndex, BYTE *data, INT32 dataSize)
{
    TPM_RC result;

    NV_DefineSpace_In defineSpace;
    memset(&defineSpace, 0, sizeof(defineSpace));
    defineSpace.authHandle = hierarchy;
    // I copied these attributes from the NV index of my laptop's TPM which contains the EK certificate
    defineSpace.publicInfo.nvPublic.attributes = attributes;
    defineSpace.publicInfo.nvPublic.nvIndex = nvIndex;
    defineSpace.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;
    defineSpace.publicInfo.nvPublic.dataSize = dataSize;

    result = TPM2_NV_DefineSpace(&defineSpace);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("TPM2_NV_DefineSpace failed with 0x%04x", result);
        return result;
    }

    NV_Write_In writeNv;
    memset(&writeNv, 0, sizeof(writeNv));
    writeNv.authHandle = hierarchy;
    writeNv.nvIndex = nvIndex;
    writeNv.data.t.size = dataSize;
    memcpy(writeNv.data.t.buffer, data, dataSize);
    result = TPM2_NV_Write(&writeNv);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("TPM2_NV_Write failed with 0x%04x", result);
        return result;
    }

    return TPM_RC_SUCCESS;
}

static void GetEkCert(uint8_t **ekCert, uint16_t *size)
{
    uint16_t chainLength = buffer_sizes[0];
    uint8_t *crt = buffer_crts;

    int i;
    for (i = 1; i < chainLength; i++)
    {
        crt += buffer_sizes[i];
    }

    *ekCert = crt;
    *size = buffer_sizes[i];
}

TPM_RC StoreEkCertificateInNvIndex()
{
    uint8_t *ekCert;
    uint16_t size;
    GetEkCert(&ekCert, &size);

    TPM_RC result = DefineAndStoreInNVIndex(
        TPM_RH_PLATFORM,
        TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | TPMA_NV_PLATFORMCREATE,
        EK_RSA_CERTIFICATE_NV_INDEX,
        ekCert, size);

    if (result != TPM_RC_SUCCESS)
    {
        DMSG("DefineAndStoreInNVIndex failed with 0x%04x", result);
        return result;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
StoreSigningEkTemplateInNvIndex()
{
    TPMT_PUBLIC publicArea;
    GetSigningEkTemplate(&publicArea);
    
    BYTE buffer[512];

    // Convert to pointer such that we can use '&buffer_ptr'
    // because for an array the '&' operator doesn't work as expected, i.e., buffer == &buffer
    // See https://stackoverflow.com/a/30194667/2050020
    BYTE* buffer_ptr = buffer;
    
    UINT16 dataSize = TPMT_PUBLIC_Marshal(&publicArea, &buffer_ptr, NULL);

    TPM_RC result = DefineAndStoreInNVIndex(
        TPM_RH_PLATFORM,
        TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | TPMA_NV_PLATFORMCREATE,
        EK_RSA_TEMPLATE_NV_INDEX,
        buffer, dataSize);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("DefineAndStoreInNVIndex failed with 0x%04x", result);
        return result;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
StoreEmptyEkNonceInNvIndex()
{
    /**
     * This is just done for the convenience that tpm2_createek works, since they don't follow the TPM spec thoroughly.
     * I reported that: https://github.com/tpm2-software/tpm2-tools/issues/3278
     */

    BYTE buffer[1] = { 0 };

    TPM_RC result = DefineAndStoreInNVIndex(
        TPM_RH_PLATFORM,
        TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | TPMA_NV_PLATFORMCREATE,
        EK_RSA_NONCE_NV_INDEX,
        buffer, sizeof(buffer));
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("DefineAndStoreInNVIndex failed with 0x%04x", result);
        return result;
    }

    return TPM_RC_SUCCESS;
}
