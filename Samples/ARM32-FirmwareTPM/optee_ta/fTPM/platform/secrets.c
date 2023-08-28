#include "secrets.h"
#include <mbedtls/md.h>
#include <string_ext.h>
#include <tee_internal_api.h>


/**
 * The CDI is simply mocked here. It was created with the command
 * dd if=/dev/urandom bs=1 count=32 status=none | xxd -i
 */
uint8_t CDI[] = {0xd4, 0x9e, 0x05, 0x71, 0xe1, 0x8f, 0x66, 0xce, 0xf6, 0x75, 0x19, 0xed,
                 0xfa, 0x79, 0xd8, 0xcb, 0xf5, 0x75, 0x3f, 0x76, 0x72, 0x44, 0x88, 0xae,
                 0x91, 0x28, 0xb4, 0x3f, 0x94, 0xaf, 0x4a, 0x04};

uint8_t storage_key[16] = { 0 };

uint8_t EPS[64] = { 0 };

static int derive_from_CDI(uint8_t *result, mbedtls_md_type_t md_type, const uint8_t *data, const size_t dataSize)
{
    // Based on this formula from [1]
    // HMAC(UDS, H(First Mutable Code))

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

    int res = mbedtls_md_hmac(md_info, CDI, sizeof(CDI), data, dataSize, result);
    if (res != 0) {
        IMSG(" failed\n  !  mbedtls_md_hmac "
             "returned -0x%04x", (unsigned int)-res);
    }
    return res;
}

static void initEPS()
{
    // Primary Seed Properties are generally defined in TPM Spec Architecture Part 1, section 14.3

    const uint8_t data[] = "ENDORSEMENT PRIMARY SEED";
    // It depends on CDI which represents the preceeding boot chain,
    // and the TCI of the fTPM TA.
    // In other words, if the fTPM TA or any component of the previous boot chain changes,
    // the EPS changes as well.
    // The EPS is 512 bits, so we need SHA512
    derive_from_CDI(EPS, MBEDTLS_MD_SHA512, data, sizeof(data));
}

static void initStorageKey()
{
    const uint8_t data[] = "DATA STORAGE KEY";
    DMSG("Storage key: %02x %02x %02x %02x", storage_key[0], storage_key[1], storage_key[2], storage_key[3]);
    derive_from_CDI(storage_key, MBEDTLS_MD_SHA1, data, sizeof(data));
    DMSG("Storage key: %02x %02x %02x %02x", storage_key[0], storage_key[1], storage_key[2], storage_key[3]);
}

/**
 * Create globals which are rooted in the CDI.
 * 
 */
void initSecrets()
{
    initEPS();
    initStorageKey();
}

void destroySecrets()
{
    memzero_explicit(CDI, sizeof(CDI));
    memzero_explicit(EPS, sizeof(EPS));
    memzero_explicit(storage_key, sizeof(storage_key));
}
