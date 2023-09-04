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
//** Description
//
//    This file contains the NV read and write access methods.  This implementation
//    uses RAM/file and does not manage the RAM/file as NV blocks.
//    The implementation may become more sophisticated over time.
//

#include "TpmError.h"
#include "Admin.h"
#include "VendorString.h"
#include "stdint.h"
#include "malloc.h"
#include "string.h"
#include "Secrets.h"

#include <string_ext.h>
#include <BaseTypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

//
// Overall size of NV, not just the TPM's NV storage
//
#define NV_CHIP_MEMORY_SIZE	(NV_MEMORY_SIZE + NV_TPM_STATE_SIZE)

//
// OpTEE still has an all or nothing approach to reads/writes. To provide
// more performant access to storage, break up NV accross 1Kbyte blocks.
//
// Note that NV_CHIP_MEMORY_SIZE *MUST* be a factor of NV_BLOCK_SIZE.
//
#define NV_BLOCK_SIZE        0x200
#define NV_BLOCK_COUNT      ((NV_CHIP_MEMORY_SIZE) / (NV_BLOCK_SIZE))

//
// For cleaner descriptor validation
//
#define IS_VALID(a) ((a) != (TEE_HANDLE_NULL))

//
// Storage flags
//
#define TA_STORAGE_FLAGS (TEE_DATA_FLAG_ACCESS_READ  | \
                          TEE_DATA_FLAG_ACCESS_WRITE | \
                          TEE_DATA_FLAG_ACCESS_WRITE_META)

//
// The base Object ID for fTPM storage
//
static const UINT32 s_StorageObjectID = 0x54504D00;	// 'TPM00'


#define CRYPTO_IV_SIZE 12
#define CRYPTO_TAG_SIZE 16

#define CRYPTO_IV_ID_OFFSET 0
#define CRYPTO_TAG_ID_OFFSET 1

static const UINT32 s_CryptoMetadataStartID = s_StorageObjectID + NV_BLOCK_COUNT;

//
// Object handle list for persistent storage objects containing NV
//
static TEE_ObjectHandle s_NVStore[NV_BLOCK_COUNT] = { TEE_HANDLE_NULL };

//
// Bitmap for NV blocks. Moving from UINT64 requires change to NV_DIRTY_ALL.
//
static UINT64 s_blockMap = 0x0ULL;

//
// Shortcut for 'dirty'ing all NV blocks. Note the type.
//
#if NV_BLOCK_COUNT < 64
#define NV_DIRTY_ALL	((UINT64)((0x1ULL << NV_BLOCK_COUNT) - 1))
#elif NV_BLOCK_COUNT == 64
#define NV_DIRTY_ALL    (~(0x0ULL))
#else
#error "NV block count exceeds 64 bit block map. Adjust block or NV size."
#endif

//
// NV state
//
static BOOL  s_NVChipFileNeedsManufacture = FALSE;
static BOOL  s_NVInitialized = FALSE;
static UCHAR s_NV[NV_CHIP_MEMORY_SIZE];

//
// Firmware revision
//
static const UINT32 firmwareV1 = FIRMWARE_V1;
static const UINT32 firmwareV2 = FIRMWARE_V2;

//
// Revision fro NVChip
//
static UINT64 s_chipRevision = 0;


// 12 byte IV is the recommended size
static TEE_ObjectHandle IV_handle = TEE_HANDLE_NULL;
static uint8_t IV_buffer[NV_BLOCK_COUNT][CRYPTO_IV_SIZE] = { 0 };

// 16 byte tag is the recommended size
static TEE_ObjectHandle tag_handle = TEE_HANDLE_NULL;
static uint8_t tag_buffer[NV_BLOCK_COUNT][CRYPTO_TAG_SIZE] = { 0 };

//
// This offset puts the revision field immediately following the TPM Admin
// state. The Admin space in NV is down to ~16 bytes but is padded out to
// 256bytes to avoid alignment issues and allow for growth.
//
#define NV_CHIP_REVISION_OFFSET ((NV_MEMORY_SIZE) + (TPM_STATE_SIZE))

#define CHECK(res, name, action) do {			\
		if ((res) != TEE_SUCCESS) {		\
			DMSG(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)


static TEE_OperationHandle encryption_op = NULL;

static TEE_Result initCryptoOp(TEE_OperationHandle *crypto_op, uint32_t mode, uint8_t *aes_key, size_t keysizeBytes)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	if (*crypto_op != NULL)
	{
		DMSG("Already initialized");
		return res;
	}

    const uint32_t keysizeBits = (uint32_t)keysizeBytes * 8;

	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	TEE_Attribute attr = { };

	res = TEE_AllocateOperation(crypto_op, TEE_ALG_AES_GCM, mode, keysizeBits);
	CHECK(res, "TEE_AllocateOperation", return res;);
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysizeBits, &hkey);
	CHECK(res, "TEE_AllocateTransientObject", return res;);

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = aes_key;
	attr.content.ref.length = keysizeBytes;

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	CHECK(res, "TEE_PopulateTransientObject", return res;);

	res = TEE_SetOperationKey(*crypto_op, hkey);
	CHECK(res, "TEE_SetOperationKey", return res;);

	TEE_FreeTransientObject(hkey);

	return TEE_SUCCESS;
}

static TEE_Result encryptBlock(TEE_OperationHandle crypto_op, uint8_t *data, size_t datalen, uint8_t *encrypted, size_t encrypted_len, uint8_t *iv_in, size_t ivlen, uint8_t *tag_out, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

    res = TEE_AEInit(crypto_op, iv_in, ivlen, tag_len * 8, 0, 0);
	CHECK(res, "TEE_AEInit", return res;);

    res = TEE_AEEncryptFinal(crypto_op, data, datalen, encrypted, &encrypted_len, tag_out, &tag_len);
	CHECK(res, "TEE_AEEncryptFinal", return res;);

    TEE_ResetOperation(crypto_op);

    return TEE_SUCCESS;
}

static TEE_Result decryptBlock(TEE_OperationHandle crypto_op, uint8_t *data, size_t datalen, uint8_t *decrypted, size_t decrypted_len, uint8_t *iv_in, size_t ivlen, uint8_t *tag_out, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

    res = TEE_AEInit(crypto_op, iv_in, ivlen, tag_len * 8, 0, 0);
	CHECK(res, "TEE_AEInit", return res;);

    res = TEE_AEDecryptFinal(crypto_op, data, datalen, decrypted, &decrypted_len, tag_out, tag_len);
	CHECK(res, "TEE_AEDecryptFinal", return res;);

    TEE_ResetOperation(crypto_op);

    return TEE_SUCCESS;
}

static void freeCryptoOp(TEE_OperationHandle *crypto_op)
{
    TEE_FreeOperation(*crypto_op);
    *crypto_op = NULL;
}

VOID
_plat__NvInitFromStorage()
{
	DMSG("_plat__NvInitFromStorage()");
	UINT32 i;
	BOOL initialized;
	UINT32 objID;
	UINT32 bytesRead;
	TEE_Result Result;

	// Don't re-initialize.
	if (s_NVInitialized) {
		return;
	}

	//
	// If the NV file is successfully read from the storage then
	// initialized must be set. We are setting initialized to true
	// here but if an error is encountered reading the NV file it will
	// be reset.
	//

	initialized = TRUE;
	//
	// We only decrypt in this function.
	// So, create the handle locally and destroy it right afterwards to not keep any unrequired resources.
	// Encryption is required much more often, so we initialize it here to a global variable.
	TEE_OperationHandle decryption_op = NULL;
	initCryptoOp(&decryption_op, TEE_MODE_DECRYPT, storage_key, sizeof(storage_key));

	// Collect storage objects and init NV.
	for (i = 0; i < NV_BLOCK_COUNT; i++) {

		// Form storage object ID for this block.
		objID = s_StorageObjectID + i;

		// Attempt to open TEE persistent storage object.
		Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
									      (void *)&objID,
									      sizeof(objID),
									      TA_STORAGE_FLAGS,
									      &s_NVStore[i]);

		// If the open failed, try to create this storage object.
		if (Result != TEE_SUCCESS) {

			// There was an error, fail the init, NVEnable can retry.
			if (Result != TEE_ERROR_ITEM_NOT_FOUND) {
#ifdef fTPMDebug
				DMSG("Failed to open fTPM storage object");
#endif
				goto Error;
			}

			// Storage object was not found, create it.
			Result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
										        (void *)&objID,
										        sizeof(objID),
										        TA_STORAGE_FLAGS,
										        NULL,
										        (void *)&(s_NV[i * NV_BLOCK_SIZE]),
										        NV_BLOCK_SIZE,
										        &s_NVStore[i]);

			// There was an error, fail the init, NVEnable can retry.
			if (Result != TEE_SUCCESS) {
#ifdef fTPMDebug
				DMSG("Failed to create fTPM storage object");
#endif
				goto Error;
			}

			// A clean storage object was created, we must (re)manufacture.
			s_NVChipFileNeedsManufacture = TRUE;

			// To ensure NV is consistent, force a write back of all NV blocks
			s_blockMap = NV_DIRTY_ALL;

			// Need to re-initialize
			initialized = FALSE;

#ifdef fTPMDebug
			IMSG("Created fTPM storage object, i: 0x%x, s: 0x%x, id: 0x%x, h:0x%x\n",
				i, NV_BLOCK_SIZE, objID, s_NVStore[i]);
#endif
		}
		else {
			// Successful open, now read fTPM storage object.

			uint8_t encrypted[NV_BLOCK_SIZE];
			Result = TEE_ReadObjectData(s_NVStore[i],
										encrypted,
										NV_BLOCK_SIZE,
										&bytesRead);

			// Give up on failed or incomplete reads.
			if ((Result != TEE_SUCCESS) || (bytesRead != NV_BLOCK_SIZE)) {
#ifdef fTPMDebug
				DMSG("Failed to read fTPM storage object");
#endif
				goto Error;
			}
			
			Result = decryptBlock(decryption_op, encrypted, NV_BLOCK_SIZE, (void *)&(s_NV[i * NV_BLOCK_SIZE]), NV_BLOCK_SIZE, IV_buffer[i], CRYPTO_IV_SIZE, tag_buffer[i], CRYPTO_TAG_SIZE);
			if (Result != TEE_SUCCESS)
			{	
				if (Result == TEE_ERROR_MAC_INVALID)
				{
					IMSG("The MAC of a block does not match.");
					IMSG("Go to failsafe mode, and clear all blocks to zero.");

					// Clear whole NV memory to zero
					memzero_explicit(s_NV, NV_CHIP_MEMORY_SIZE);
					
					// Re-Initialize all blocks, set to 0
					for (i = 0; i < NV_BLOCK_COUNT; i++) {
						if (s_NVStore[i] != TEE_HANDLE_NULL)
							TEE_CloseObject(s_NVStore[i]);
						objID = s_StorageObjectID + i;
						Result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
										        (void *)&objID,
										        sizeof(objID),
										        TA_STORAGE_FLAGS | TEE_DATA_FLAG_OVERWRITE,
										        TEE_HANDLE_NULL,
										        (void *)&(s_NV[i * NV_BLOCK_SIZE]),
										        NV_BLOCK_SIZE,
										        &s_NVStore[i]);
						#ifdef fTPMDebug
							IMSG("Re-initialized fTPM storage object, i: 0x%02x, s: 0x%02x, id: 0x%02x, h:0x%02x\n",
								i, NV_BLOCK_SIZE, objID, s_NVStore[i]);
						#endif
					}

					break;
				}
				else
				{
					CHECK(Result, "decryptBlock", return Result;);
				}
			}

#ifdef fTPMDebug
			IMSG("Read fTPM storage object, i: 0x%x, s: 0x%x, id: 0x%x, h:0x%x\n",
				i, bytesRead, objID, s_NVStore[i]);
#endif
		}
	}

	freeCryptoOp(&decryption_op);

	// Storage objects are open and valid, next validate revision
	s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
	if ((s_chipRevision != *(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]))) {

		// Failure to validate revision, re-init.
		memset(s_NV, 0, NV_CHIP_MEMORY_SIZE);

		// Dirty the block map, we're going to re-init.
		s_blockMap = NV_DIRTY_ALL;

		// Init with proper revision
		s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
		*(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]) = s_chipRevision;

#ifdef fTPMDebug
		DMSG("Failed to validate revision.");
#endif

		// Force (re)manufacture.
		s_NVChipFileNeedsManufacture = TRUE;

		// Need to re-initialize
		initialized = FALSE;

		return;
	}

	s_NVInitialized = initialized;

	return;

Error:
	s_NVInitialized = FALSE;
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}
	memzero_explicit(s_NV, NV_CHIP_MEMORY_SIZE);
	TEE_CloseObject(IV_handle);
	TEE_CloseObject(tag_handle);
	IV_handle = TEE_HANDLE_NULL;
	tag_handle = TEE_HANDLE_NULL;

	return;
}


static void
_plat__NvWriteBack()
{
    UINT32 i;
	UINT32 objID;
	TEE_Result Result;

	// Exit if no dirty blocks.
	if ((!s_blockMap) || (!s_NVInitialized)) {
		return;
	}

#ifdef fTPMDebug
	DMSG("bMap: 0x%x\n", s_blockMap);
#endif

	// Write dirty blocks.
    for (i = 0; i < NV_BLOCK_COUNT; i++) {

        if ((s_blockMap & (0x1ULL << i))) {

			// Form storage object ID for this block.
			objID = s_StorageObjectID + i;
            
			// Move data position associated with handle to start of block.
            Result = TEE_SeekObjectData(s_NVStore[i], 0, TEE_DATA_SEEK_SET);
			if (Result != TEE_SUCCESS) {
				goto Error;
			}
			Result = TEE_SeekObjectData(IV_handle, 0, TEE_DATA_SEEK_SET);
			if (Result != TEE_SUCCESS) {
				goto Error;
			}
			Result = TEE_SeekObjectData(tag_handle, 0, TEE_DATA_SEEK_SET);
			if (Result != TEE_SUCCESS) {
				goto Error;
			}

			// Generate new IV at each write to hard drive
			TEE_GenerateRandom(IV_buffer[i], CRYPTO_IV_SIZE);

			uint8_t encrypted[NV_BLOCK_SIZE];
			Result = encryptBlock(encryption_op, (void *)&(s_NV[i * NV_BLOCK_SIZE]), NV_BLOCK_SIZE, encrypted, NV_BLOCK_SIZE, IV_buffer[i], CRYPTO_IV_SIZE, tag_buffer[i], CRYPTO_TAG_SIZE);
        	CHECK(Result, "encryptBlock", return Result;);

			// Write out this block.
            Result = TEE_WriteObjectData(s_NVStore[i],
									     encrypted,
                                         NV_BLOCK_SIZE);
			if (Result != TEE_SUCCESS) {
				goto Error;
			}
            
			// Force storage stack to update its backing store
            TEE_CloseObject(s_NVStore[i]);
            
            Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              (void *)&objID,
                                              sizeof(objID),
                                              TA_STORAGE_FLAGS,
                                              &s_NVStore[i]);
			// Success?
			if (Result != TEE_SUCCESS) {
				goto Error;
			}

			Result = TEE_WriteObjectData(IV_handle, IV_buffer, sizeof(IV_buffer));
			CHECK(Result, "TEE_WriteObjectData", goto Error;);
			Result = TEE_WriteObjectData(tag_handle, tag_buffer, sizeof(tag_buffer));
			CHECK(Result, "TEE_WriteObjectData", goto Error;);

			UINT32 ivObjID = s_CryptoMetadataStartID + CRYPTO_IV_ID_OFFSET;
			UINT32 tagObjID = s_CryptoMetadataStartID + CRYPTO_TAG_ID_OFFSET;

			TEE_CloseObject(IV_handle);
            Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              (void *)&ivObjID,
                                              sizeof(ivObjID),
                                              TA_STORAGE_FLAGS,
                                              &IV_handle);
			if (Result != TEE_SUCCESS) {
				DMSG("Failed to reopen IV handle");
			}


			TEE_CloseObject(tag_handle);
            Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              (void *)&tagObjID,
                                              sizeof(tagObjID),
                                              TA_STORAGE_FLAGS,
                                              &tag_handle);

			if (Result != TEE_SUCCESS) {
				DMSG("Failed to reopen Tag handle");
			}

			// Clear dirty bit.
            s_blockMap &= ~(0x1ULL << i);
        }
    }

    return;

Error:
	// Error path.
#ifdef fTPMDebug
	DMSG("NV write back failed");
#endif
	s_NVInitialized = FALSE;
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}
	memzero_explicit(s_NV, NV_CHIP_MEMORY_SIZE);
	TEE_CloseObject(IV_handle);
	TEE_CloseObject(tag_handle);
	IV_handle = TEE_HANDLE_NULL;
	tag_handle = TEE_HANDLE_NULL;

	return;
}


BOOL
_plat__NvNeedsManufacture()
{
    return s_NVChipFileNeedsManufacture;
}

static TEE_Result initIVAndTagBlocks()
{
	TEE_Result Result;
	UINT32 ivObjID = s_CryptoMetadataStartID + CRYPTO_IV_ID_OFFSET;
	UINT32 tagObjID = s_CryptoMetadataStartID + CRYPTO_TAG_ID_OFFSET;

	Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
										&ivObjID,
										sizeof(ivObjID),
										TA_STORAGE_FLAGS,
										&IV_handle);
	if (Result != TEE_SUCCESS)
	{
		Result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
										&ivObjID,
										sizeof(ivObjID),
										TA_STORAGE_FLAGS,
										TEE_HANDLE_NULL,
										IV_buffer,
										sizeof(IV_buffer),
										&IV_handle);
		CHECK(Result, "TEE_CreatePersistentObject", return Result;);
	} else {
		size_t actuallyRead = 0;
		Result = TEE_ReadObjectData(IV_handle, IV_buffer, sizeof(IV_buffer), &actuallyRead);
		CHECK(Result, "TEE_ReadObjectData", return Result;);
		if (actuallyRead != sizeof(IV_buffer))
		{
			DMSG("Failed to read IV block. Expected %d bytes, got %d bytes.", sizeof(IV_buffer), actuallyRead);
		}
	}

	
	Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
										&tagObjID,
										sizeof(tagObjID),
										TA_STORAGE_FLAGS,
										&tag_handle);
	if (Result != TEE_SUCCESS)
	{
		Result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
											&tagObjID,
											sizeof(tagObjID),
											TA_STORAGE_FLAGS,
											TEE_HANDLE_NULL,
											tag_buffer,
											sizeof(tag_buffer),
											&tag_handle);
		CHECK(Result, "TEE_CreatePersistentObject", return Result;);
	} else {
		size_t actuallyRead = 0;
		Result = TEE_ReadObjectData(tag_handle, tag_buffer, sizeof(tag_buffer), &actuallyRead);
		CHECK(Result, "TEE_ReadObjectData", return Result;);
		if (actuallyRead != sizeof(tag_buffer))
		{
			DMSG("Failed to read tag block. Expected %d bytes, got %d bytes.", sizeof(tag_buffer), actuallyRead);
		}
	}
}

//***_plat__NVEnable()
// Enable NV memory.
//
// This version just pulls in data from a file. In a real TPM, with NV on chip,
// this function would verify the integrity of the saved context. If the NV
// memory was not on chip but was in something like RPMB, the NV state would be
// read in, decrypted and integrity checked.
//
// The recovery from an integrity failure depends on where the error occurred. It
// it was in the state that is discarded by TPM Reset, then the error is
// recoverable if the TPM is reset. Otherwise, the TPM must go into failure mode.
// return type: int
//      0           if success
//      > 0         if receive recoverable error
//      <0          if unrecoverable error
LIB_EXPORT int
_plat__NVEnable(
    void            *platParameter  // IN: platform specific parameters
	)
{
    UNREFERENCED_PARAMETER(platParameter);
	DMSG("_plat__NVEnable()");


    UINT32 retVal = 0;
    UINT32 firmwareV1 = FIRMWARE_V1;
    UINT32 firmwareV2 = FIRMWARE_V2;

    // Don't re-open the backing store.
    if (s_NVInitialized) {
        return 0;
    }

	// Clear NV
    memset(s_NV, 0, NV_CHIP_MEMORY_SIZE);

    // Prepare for potential failure to retreieve NV from storage
    s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
    *(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]) = s_chipRevision;

	initIVAndTagBlocks();
	initCryptoOp(&encryption_op, TEE_MODE_ENCRYPT, storage_key, sizeof(storage_key));

    // Pick up our NV memory.
    _plat__NvInitFromStorage();

    // Were we successful?
    if (!s_NVInitialized) {
        // Arriving here means one of two things: Either there existed no
        // NV state before we came along and we just (re)initialized our
        // storage. Or there is an error condition preventing us from 
        // accessing storage.  Check which is the case.
        if (s_NVChipFileNeedsManufacture == FALSE) {
            // This condition means we cannot access storage. However, it
            // isn't up to the platform layer to decide what to do in this
            // case. The decision to proceed is made in the fTPM init code
            // in TA_CreateEntryPoint. Here, we're going to make sure that,
            // should we decide not to just TEE_Panic, we can continue
            // execution after (re)manufacture. Later an attempt at re-init
            // can be made by calling _plat__NvInitFromStorage again.
            retVal = 0;
        }
        else {
            retVal = 1;
        }

        // Going to manufacture, zero flags
        g_chipFlags.flags = 0;

        // Save flags
        _admin__SaveChipFlags();

        // Now we're done
        s_NVInitialized = TRUE;

        return retVal;
    }
    else {
        // In the transition out of UEFI to Windows, we may not tear down
        // the TA. We close out one session and start another. This means
        // our s_NVChipFileNeedsManufacture flag, if set, will be stale.
        // Make sure we don't re-manufacture.
        s_NVChipFileNeedsManufacture = FALSE;

        // We successfully initialized NV now pickup TPM state.
        _admin__RestoreChipFlags();

		// Success
		retVal = 1;
    }

    return retVal;
}

//***_plat__NVDisable()
// Disable NV memory
LIB_EXPORT void
_plat__NVDisable(
    void
    )
{
	UINT32 i;

    if (!s_NVInitialized) {
        return;
    }

	// Final write
    _plat__NvWriteBack();

	// Close out all handles
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}
	memzero_explicit(s_NV, NV_CHIP_MEMORY_SIZE);
	TEE_CloseObject(IV_handle);
	TEE_CloseObject(tag_handle);
	IV_handle = TEE_HANDLE_NULL;
	tag_handle = TEE_HANDLE_NULL;

	freeCryptoOp(&encryption_op);

	// We're no longer init-ed
	s_NVInitialized = FALSE;

    return;
}

//***_plat__IsNvAvailable()
// Check if NV is available
// return type: int
//      0               NV is available
//      1               NV is not available due to write failure
//      2               NV is not available due to rate limit
LIB_EXPORT int
_plat__IsNvAvailable(
    void
    )
{
    // This is not enabled for OpTEE TA. Storage is always available.
    return 0;
}



//***_plat__NvMemoryRead()
// Function: Read a chunk of NV memory
LIB_EXPORT void
_plat__NvMemoryRead(
    unsigned int     startOffset,   // IN: read start
    unsigned int     size,          // IN: size of bytes to read
    void            *data           // OUT: data buffer
    )
{
    pAssert((startOffset + size) <= NV_CHIP_MEMORY_SIZE);
    pAssert(s_NV != NULL);

    memcpy(data, &s_NV[startOffset], size);
}

//*** _plat__NvIsDifferent()
// This function checks to see if the NV is different from the test value. This is
// so that NV will not be written if it has not changed.
// return value: int
//  TRUE(1)    the NV location is different from the test value
//  FALSE(0)   the NV location is the same as the test value
LIB_EXPORT int
_plat__NvIsDifferent(
    unsigned int     startOffset,   // IN: read start
    unsigned int     size,          // IN: size of bytes to read
    void            *data           // IN: data buffer
    )
{
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}

static
void
_plat__MarkDirtyBlocks (
	unsigned int		startOffset,
	unsigned int		size
)
{
	unsigned int blockEnd;
	unsigned int blockStart;	
	unsigned int i;
	
	//
	// Integer math will round down to the start of the block.
	// blockEnd is actually the last block + 1.
	//

	blockStart = startOffset / NV_BLOCK_SIZE;
	blockEnd = (startOffset + size) / NV_BLOCK_SIZE;
	if ((startOffset + size) % NV_BLOCK_SIZE != 0) {
		blockEnd += 1;
	}

	for (i = blockStart; i < blockEnd; i++) {
		s_blockMap |= (0x1ULL << i);
	}
}

//***_plat__NvMemoryWrite()
// This function is used to update NV memory. The "write" is to a memory copy of
// NV. At the end of the current command, any changes are written to
// the actual NV memory.
// NOTE: A useful optimization would be for this code to compare the current 
// contents of NV with the local copy and note the blocks that have changed. Then
// only write those blocks when _plat__NvCommit() is called.
LIB_EXPORT void
_plat__NvMemoryWrite(
    unsigned int     startOffset,   // IN: write start
    unsigned int     size,          // IN: size of bytes to write
    void            *data           // OUT: data buffer
    )
{
    pAssert(startOffset + size <= NV_CHIP_MEMORY_SIZE);
    pAssert(s_NV != NULL);

	_plat__MarkDirtyBlocks(startOffset, size);
    memcpy(&s_NV[startOffset], data, size);
}

//***_plat__NvMemoryClear()
// Function is used to set a range of NV memory bytes to an implementation-dependent
// value. The value represents the erase state of the memory.
LIB_EXPORT void
_plat__NvMemoryClear(
    unsigned int     start,         // IN: clear start
    unsigned int     size           // IN: number of bytes to clear
    )
{
    pAssert(start + size <= NV_MEMORY_SIZE);

	_plat__MarkDirtyBlocks(start, size);
    memset(&s_NV[start], 0, size);
}

//***_plat__NvMemoryMove()
// Function: Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
LIB_EXPORT void
_plat__NvMemoryMove(
    unsigned int     sourceOffset,  // IN: source offset
    unsigned int     destOffset,    // IN: destination offset
    unsigned int     size           // IN: size of data being moved
    )
{
    pAssert(sourceOffset + size <= NV_CHIP_MEMORY_SIZE);
    pAssert(destOffset + size <= NV_CHIP_MEMORY_SIZE);
    pAssert(s_NV != NULL);

	_plat__MarkDirtyBlocks(sourceOffset, size);
	_plat__MarkDirtyBlocks(destOffset, size);

    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
}

//***_plat__NvCommit()
// This function writes the local copy of NV to NV for permanent store. It will write
// NV_MEMORY_SIZE bytes to NV. If a file is use, the entire file is written.
// return type: int
//  0       NV write success
//  non-0   NV write fail
LIB_EXPORT int
_plat__NvCommit(
    void
    )
{
    _plat__NvWriteBack();
    return 0;
}

//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__SetNvAvail(
    void
    )
{
    // NV will not be made unavailable on this platform
    return;
}

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__ClearNvAvail(
    void
    )
{
    // The anti-set; not on this platform.
    return;
}
