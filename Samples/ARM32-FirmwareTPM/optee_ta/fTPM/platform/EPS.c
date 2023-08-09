/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// Platform Endorsement Primary Seed
//

#include "TpmError.h"
#include "Admin.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <mbedtls/md.h>

/*
According to [1], "the DICE creates this CDI using a one-way function with at least the same security strength as the
attestation process."

Our TCIs are SHA256 values. So, the CDI should be 256 bits as well.
The CDI is simply mocked here. It was created with the command
dd if=/dev/urandom bs=1 count=32 status=none | xxd -i


[1] Hardware Requirements for a Device Identifier Composition Engine
*/

static uint8_t CDI[] = {0xd4, 0x9e, 0x05, 0x71, 0xe1, 0x8f, 0x66, 0xce, 0xf6, 0x75, 0x19, 0xed,
  0xfa, 0x79, 0xd8, 0xcb, 0xf5, 0x75, 0x3f, 0x76, 0x72, 0x44, 0x88, 0xae,
  0x91, 0x28, 0xb4, 0x3f, 0x94, 0xaf, 0x4a, 0x04};

static int hmac_sha512(uint8_t *result, const void *data, const size_t dataSize, const uint8_t *key,
				   const size_t keySize)
{
	const mbedtls_md_info_t *info_sha512 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

	return mbedtls_md_hmac(info_sha512, key, keySize, data, dataSize, result);
}

void
_plat__GetEPS(uint16_t Size, uint8_t *EndorsementSeed)
{
    // The EPS is 512 bits, so we need SHA512
    char sha512_buf[64]; // TODO: Maybe replace constant 64 with a definition provided by TPM, e.g., PRIMARY_SEED_SIZE
    char data[] = "EPS";
    int res;

    IMSG("Requested EPS Size = %" PRIu16 "", Size);
    
    pAssert(Size <= 64);

    // Based on this formula from [1]
    // HMAC(UDS, H(First Mutable Code))
    // It depends on CDI which represents the previous boot chain,
    // and it also depends on the TCI of the fTPM TA.
    // In other words, if the fTPM TA or any component of the previous boot chain changes,
    // the EPS changes as well.
    res = hmac_sha512(sha512_buf, data, sizeof(data), CDI, sizeof(CDI));

    memcpy(EndorsementSeed, sha512_buf, Size);

     // We don't need the CDI anymore. Erase it to make it less likely to be leaked
    memzero_explicit(CDI, sizeof(CDI));

    if (res != 0) {
        IMSG(" failed\n  !  hmac_sha512 "
             "returned -0x%04x", (unsigned int)-res);
    }

#ifdef fTPMDebug
    {
        uint32_t x;
        uint8_t *seed = EndorsementSeed;
        DMSG("seedLen 0x%x. Seed dump:\n", Size);
        for (x = 0; x < Size; x = x + 8) {
            DMSG("%08x: %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                 seed[x + 0], seed[x + 1], seed[x + 2], seed[x + 3],
                 seed[x + 4], seed[x + 5], seed[x + 6], seed[x + 7]);
        }
    }
#endif
}
