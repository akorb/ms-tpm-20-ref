#include "Secrets.h"
#include "EK.h"
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <string_ext.h>
#include <tee_internal_api.h>


/*
 * Do not change the order of these includes!
 * The behavior of the inclusion of Tpm.h is modified by TpmProfile.h.
 * The include of Tpm.h alone would fail.
 */
#include <TpmProfile.h>
#include <Tpm.h>


/*************** SHORT TERM SECRETS *************************/

/**
 * The CDI is simply mocked here. It was created with the command
 * dd if=/dev/urandom bs=1 count=32 status=none | xxd -i
 */
uint8_t CDI[] = {0xd4, 0x9e, 0x05, 0x71, 0xe1, 0x8f, 0x66, 0xce, 0xf6, 0x75, 0x19, 0xed,
                 0xfa, 0x79, 0xd8, 0xcb, 0xf5, 0x75, 0x3f, 0x76, 0x72, 0x44, 0x88, 0xae,
                 0x91, 0x28, 0xb4, 0x3f, 0x94, 0xaf, 0x4a, 0x04};

uint8_t storage_key[32] = { 0 };

uint8_t EPS[64] = { 0 };


/*************** LONG TERM SECRETS *************************/

TPMT_SENSITIVE EkSigningPrivKey = { 0 };
TPMT_PUBLIC EkSigningPubKey = { 0 };

static int derive_from_CDI(uint8_t *dst, const size_t dstSize, mbedtls_md_type_t md_type, const uint8_t *data, const size_t dataSize)
{
    // Based on this formula from [1]
    // HMAC(UDS, H(First Mutable Code))

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (dstSize < md_info->size)
    {
        EMSG("Didn't provide big enough buffer to store secret in.");
        return 1;
    }

    int res = mbedtls_md_hmac(md_info, CDI, sizeof(CDI), data, dataSize, dst);
    if (res != 0) {
        IMSG(" failed\n  !  mbedtls_md_hmac "
             "returned -0x%04x", (unsigned int)-res);
    }
    return res;
}

void initEPS()
{
    // General Primary Seed properties are defined in TPM Spec Architecture Part 1, section 14.3

    const uint8_t data[] = "ENDORSEMENT PRIMARY SEED";
    // It depends on CDI which represents the preceeding boot chain,
    // and the TCI of the fTPM TA.
    // In other words, if the fTPM TA or any component of the previous boot chain changes,
    // the EPS changes as well.
    // The EPS is 512 bits, so we need SHA512
    derive_from_CDI(EPS, sizeof(EPS), MBEDTLS_MD_SHA512, data, sizeof(data));

#ifdef fTPMDebug
    {
        DMSG("seedLen 0x%x. Seed dump:\n", sizeof(EPS));
        for (uint32_t x = 0; x < sizeof(EPS); x = x + 8) {
            DMSG("%08x: %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                 EPS[x + 0], EPS[x + 1], EPS[x + 2], EPS[x + 3],
                 EPS[x + 4], EPS[x + 5], EPS[x + 6], EPS[x + 7]);
        }
    }
#endif
}

void initStorageKey()
{
    const uint8_t data[] = "DATA STORAGE KEY";
    derive_from_CDI(storage_key, sizeof(storage_key), MBEDTLS_MD_SHA256, data, sizeof(data));
}


void initEkKeys()
{
    TPM_RC result;

    TPM2B_SEED seed;
    memset(&seed, 0, sizeof(seed));
    memcpy(seed.t.buffer, EPS, sizeof(EPS));
    seed.t.size = sizeof(EPS);

    const char *buffer = seed.b.buffer;

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

    result = GetEkTemplate(&publicArea);
    if (result != TPM_RC_SUCCESS)
    {
        EMSG("GetEkTemplate failed with 0x%02x", result);
        return;
    }

    // The following code is copied and adapted from the `TPM2_CreatePrimary` function.
    // The `TPM2_CreatePrimary` function creates a transient object to store the key in,
    // we don't want that. We really only want to get a buffer with the key, that's all. No side-effects.
    result = DRBG_InstantiateSeeded(&rand,
                                    &seed.b,
                                    PRIMARY_OBJECT_CREATION,
                                    (TPM2B *)PublicMarshalAndComputeName(&publicArea, &name),
                                    &inSensitive.sensitive.data.b);
    if (result != TPM_RC_SUCCESS)
    {
        EMSG("DRBG_InstantiateSeeded failed with 0x%x", result);
        return;
    }

    result = CryptRsaGenerateKey(&publicArea, &sensitive, &rand);
    if (result != TPM_RC_SUCCESS)
    {
        EMSG("CryptRsaGenerateKey failed with 0x%x", result);
        return;
    }

    EkSigningPubKey = publicArea;
    EkSigningPrivKey = sensitive;

#ifdef fTPMDebug
    BYTE *pubKey = EkSigningPubKey.unique.rsa.t.buffer;
    UINT16 pubKeySize = EkSigningPubKey.unique.rsa.t.size;
    DMSG("Public key length: 0x%02x. Dump:\n", pubKeySize);
    for (UINT16 x = 0; x < pubKeySize; x += 8) {
        DMSG("%08x: %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                pubKey[x + 0], pubKey[x + 1], pubKey[x + 2], pubKey[x + 3],
                pubKey[x + 4], pubKey[x + 5], pubKey[x + 6], pubKey[x + 7]);
    }
#endif
}

void destroyShortlivingSecrets()
{
    memzero_explicit(CDI, sizeof(CDI));
    memzero_explicit(EPS, sizeof(EPS));
    memzero_explicit(storage_key, sizeof(storage_key));
}

void destroyAllSecrets()
{
    destroyShortlivingSecrets();
    memzero_explicit(&EkSigningPrivKey, sizeof(EkSigningPrivKey));
}
