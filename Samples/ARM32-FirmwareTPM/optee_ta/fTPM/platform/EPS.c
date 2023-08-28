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
#include <Tpm.h>
#include "secrets.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


void
_plat__GetEPS(uint16_t Size, uint8_t *EndorsementSeed)
{
    IMSG("Requested EPS Size = %" PRIu16 "", Size);
    pAssert(Size <= 64);
    memcpy(EndorsementSeed, EPS, Size);

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

void updateEPS()
{
    _plat__GetEPS(gp.EPSeed.t.size, gp.EPSeed.t.buffer);
    NV_SYNC_PERSISTENT(EPSeed);
    DMSG("Updated EPS");
}
