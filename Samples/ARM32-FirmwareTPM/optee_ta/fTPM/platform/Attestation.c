#include "Attestation.h"
#include <stdint.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_attestation.h>


uint8_t buffer_crts[5000] = { 0 };
uint16_t buffer_sizes[8] = { 0 };

TEE_Result do_attestation(const char *ekPub, const size_t ekPubLen)
{
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
