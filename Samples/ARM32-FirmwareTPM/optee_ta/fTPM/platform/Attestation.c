#include "Attestation.h"
#include <stdint.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_attestation.h>

/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>

#include "Secrets.h"

#include <CryptRsa_fp.h>
#include <Hash_fp.h>

uint8_t buffer_crts[5000] = { 0 };
uint16_t buffer_sizes[8] = { 0 };

#define CHECK(res, name, action) do {			\
		if ((res) != TEE_SUCCESS) {		\
			DMSG(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)

TEE_Result hashSha256(const char *data, const size_t dataSize, char *hashOut, size_t hashOutSize)
{
    // Do this with TEE functions instead of TPM functions,
    // since like this the code is much easier,
    // because here the TEE functions handle all the separations in the right chunk sizes,
    // while with the TPM we'd need to do that ourselves.

    if (hashOutSize < SHA256_DIGEST_SIZE)
    {
        EMSG("Provided too short buffer to store SHA256 buffer in.");
        return TEE_ERROR_SHORT_BUFFER;
    }

	TEE_Result res = TEE_ERROR_GENERIC;
    TEE_OperationHandle hash_op = NULL;

	res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	CHECK(res, "TEE_AllocateOperation", return res;);

    res = TEE_DigestDoFinal(hash_op, data, dataSize, hashOut, &hashOutSize);
	CHECK(res, "TEE_DigestDoFinal", return res;);

    TEE_FreeOperation(hash_op);

    return TEE_SUCCESS;
}

TPM_RC sign_nonce(const char *nonce, const size_t nonceSize, char *outputBuf, size_t *outputBufSize)
{
    TPM_RC result;
    TPMT_SIGNATURE signature;
    OBJECT key;
    TPM2B_DIGEST digest;
    memset(&signature, 0, sizeof(signature));
    memset(&key, 0, sizeof(key));
    memset(&digest, 0, sizeof(digest));

    TEE_Result res = hashSha256(nonce, nonceSize, digest.t.buffer, SHA256_DIGEST_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("hash failed with 0x%02x", res);
        return TPM_RC_FAILURE;
    }
    digest.t.size = SHA256_DIGEST_SIZE;

    signature.sigAlg = TPM_ALG_RSASSA;
    signature.signature.rsassa.hash = TPM_ALG_SHA256;

    key.publicArea = EkSigningPubKey;
    key.sensitive = EkSigningPrivKey;

    result = CryptRsaSign(&signature, &key, &digest, NULL);
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("CryptRsaSign failed with 0x%02x", result);
        return TPM_RC_FAILURE;
    }

    if (outputBufSize < signature.signature.rsassa.sig.t.size)
    {
        EMSG("Buffer too small to store signature in.");
        return TPM_RC_MEMORY;
    }

    memcpy(outputBuf, signature.signature.rsassa.sig.t.buffer, signature.signature.rsassa.sig.t.size);
    *outputBufSize = signature.signature.rsassa.sig.t.size;

    // keep as less copies of secrets as possible
    memzero_explicit(&key.sensitive, sizeof(key.sensitive));

    DMSG("Signature:");
    for (int x = 0; x < sizeof(signature.signature.rsassa.sig.t.buffer); x += 8)
    {
        DMSG("%08x: %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                    signature.signature.rsassa.sig.t.buffer[x + 0], signature.signature.rsassa.sig.t.buffer[x + 1], signature.signature.rsassa.sig.t.buffer[x + 2], signature.signature.rsassa.sig.t.buffer[x + 3],
                    signature.signature.rsassa.sig.t.buffer[x + 4], signature.signature.rsassa.sig.t.buffer[x + 5], signature.signature.rsassa.sig.t.buffer[x + 6], signature.signature.rsassa.sig.t.buffer[x + 7]);
    }

    return result;
}

TEE_Result do_attestation()
{
    BYTE *ekPub = EkSigningPubKey.unique.rsa.t.buffer;
    UINT16 ekPubLen = EkSigningPubKey.unique.rsa.t.size;

    uint32_t param_types = 0;
    TEE_Param params[TEE_NUM_PARAMS] = { };

    TEE_TASessionHandle session = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_GENERIC;
    uint32_t ret_origin = 0;
    const TEE_UUID pta_uuid = PTA_ATTESTATION_UUID;

    res = TEE_OpenTASession(&pta_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &session, &ret_origin);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x",
             res, ret_origin);
        return res;
    }

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);

    params[0].memref.buffer = buffer_crts;
    params[0].memref.size = sizeof(buffer_crts);

    params[1].memref.buffer = buffer_sizes;
    params[1].memref.size = sizeof(buffer_sizes);

    params[2].memref.buffer = ekPub;
    params[2].memref.size = ekPubLen;

    res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
                              PTA_ATTESTATION_GET_EKCERT_CHAIN,
                              param_types, params, &ret_origin);
    TEE_CloseTASession(session);

    if (res != TEE_SUCCESS) {
        EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x",
             res, ret_origin);
        return res;
    }

    return TEE_SUCCESS;
}
