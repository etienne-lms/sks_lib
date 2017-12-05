/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_H__
#define __SKS_TA_H__

#include <sys/types.h>
#include <stdint.h>

#define TA_SKS_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
                        { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

#define KEYCMD			0
#define PROCCMD			1
#define DEBUGCMD		2
#define CRYPTOKICMD		3

#define TA_SKS_CMD_REQUEST_MASK		0xFFFFFFF

#define TA_SKS_CMD_KEY(cmd)		((cmd) | (KEYCMD << 28))
#define TA_SKS_CMD_PROCESSING(cmd)	((cmd) | (PROCCMD << 28))
#define TA_SKS_CMD_DEBUG(cmd)		((cmd) | (DEBUGCMD << 28))
#define TA_SKS_CMD_CRYPTOKI(cmd)	((cmd) | (CRYPTOKICMD << 28))

#define TA_SKS_CMD(cmd)		((cmd) | (CKCMD << 28))
#define TA_SKS_CMD2REQ(cmd)	((cmd) & TA_SKS_CMD_REQUEST_MASK)

/*
 * PKCS#11 specific behaviour against token/session/login.
 * Specific request from the the cryptoki API
 *
 * SKS_CMD_CK_PING			do nothing but invoke the SKS TA.
 * SKS_CMD_CK_SLOTS_INFO		get slot IDs (+ info) supported by the TA.
 * SKS_CMD_CK_GET_TOKEN_INFO		get token info (Cpryptoki)
 */

/*
 * request args:	none
 * input data:		none
 * output data:		none
 */
#define SKS_CMD_CK_PING			TA_SKS_CMD_CRYPTOKI(0x000000)

/*
 * request args:	none
 * input data:		none
 * output data:		table of struct sks_ck_slot_info, size gives item count
 */
#define SKS_CMD_CK_SLOTS_INFO		TA_SKS_CMD_CRYPTOKI(0x000001)

struct sks_ck_slot_info {
	uint8_t slotDescription[64];
	uint8_t manufacturerID[32];
	uint32_t flags;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
};

/*
 * request args:	slot ID
 * input data:		none
 * output data:		[sks-token-info]
 */
#define SKS_CMD_CK_TOKEN_INFO		TA_SKS_CMD_CRYPTOKI(0x000002)

struct sks_ck_token_info {
	uint8_t label[32];
	uint8_t manufacturerID[32];
	uint8_t model[16];
	uint8_t serialNumber[16];
	uint32_t flags;
	uint32_t ulMaxSessionCount;
	uint32_t ulSessionCount;
	uint32_t ulMaxRwSessionCount;
	uint32_t ulRwSessionCount;
	uint32_t ulMaxPinLen;
	uint32_t ulMinPinLen;
	uint32_t ulTotalPublicMemory;
	uint32_t ulFreePublicMemory;
	uint32_t ulTotalPrivateMemory;
	uint32_t ulFreePrivateMemory;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
	uint8_t utcTime[16];
};

/*
 * Get list of the supported mechanisms
 * request args:	none
 * input data:		none
 * output data:		[array-of-sks-mechanism_IDs]
 */
#define SKS_CMD_CK_MECHANISM_IDS	TA_SKS_CMD_CRYPTOKI(0x000003)

/*
 * Open Read-Only Session
 * request args:	[sks-mechanism-id]
 * input data:		none
 * output data:		[sks-mechanism-info]
 */
#define SKS_CMD_CK_MECHANISM_INFO	TA_SKS_CMD_CRYPTOKI(0x000004)

/*
 * Initialiaze PKCS#11 token
 * request args:	[pin-length][pin-value][32byte-label]
 * input data:		none
 * output data:		[sks-mechanism-info)]
 */
#define SKS_CMD_CK_INIT_TOKEN		TA_SKS_CMD_CRYPTOKI(0x000005)

/*
 * Initialiaze PKCS#11 token PIN
 * request args:	[sks-session-handle][pin-length][pin-value]
 * input data:		none
 * output data:		none
 */
#define SKS_CMD_CK_INIT_PIN		TA_SKS_CMD_CRYPTOKI(0x000006)

/*
 * Set PKCS#11 token PIN
 * request args:	[sks-session-handle][old-len][old-pin][new-len][new-pin]
 * input data:		none
 * output data:		none
 */
#define SKS_CMD_CK_SET_PIN		TA_SKS_CMD_CRYPTOKI(0x000007)

/*
 * Open Read-only Session
 * request args:	slot ID
 * input data:		none
 * output data:		[sks-session-handle]
 */
#define SKS_CMD_CK_OPEN_RO_SESSION	TA_SKS_CMD_CRYPTOKI(0x000008)

/*
 * Open Read/Write Session
 * request args:	slot ID
 * input data:		none
 * output data:		[sks-session-handle]
 */
#define SKS_CMD_CK_OPEN_RW_SESSION	TA_SKS_CMD_CRYPTOKI(0x000009)

/*
 * Close Session
 * request args:	[sks-session-handle]
 * input data:		none
 * output data:		none
 */
#define SKS_CMD_CK_CLOSE_SESSION	TA_SKS_CMD_CRYPTOKI(0x00000a)

/*
 * Get session information
 * request args:	[sks-session-handle]
 * input data:		none
 * output data:		[sks-session-info]
 */
#define SKS_CMD_CK_SESSION_INFO		TA_SKS_CMD_CRYPTOKI(0x00000b)

/*
 * request args:	[sks-session-handle][sks-attributes-blob]
 * input data:		none
 * output data:		[sks-object-handle]
 */
#define SKS_CMD_CK_CREATE_OBJECT	TA_SKS_CMD_KEY(0x000001)
#define SKS_CMD_CK_DESTROY_OBJECT	TA_SKS_CMD_KEY(0x000002)

/*
 * request args:	[sks-session-handle][sks-mechanism-blob]
 * input data:		none
 * output data:		none
 */
#define SKS_CMD_CK_ENCRYPT_INIT		TA_SKS_CMD_PROCESSING(0x000001)
#define SKS_CMD_CK_DECRYPT_INIT		TA_SKS_CMD_PROCESSING(0x000002)

/*
 * request args:	[sks-session-handle]
 * input data:		yes
 * output data:		yes
 */
#define SKS_CMD_CK_ENCRYPT_UPDATE	TA_SKS_CMD_PROCESSING(0x000003)
#define SKS_CMD_CK_DECRYPT_UPDATE	TA_SKS_CMD_PROCESSING(0x000004)

/*
 * request args:	[sks-session-handle]
 * input data:		none
 * output data:		yes
 */
#define SKS_CMD_CK_DECRYPT_FINAL	TA_SKS_CMD_PROCESSING(0x000005)
#define SKS_CMD_CK_ENCRYPT_FINAL	TA_SKS_CMD_PROCESSING(0x000006)

#endif /* __SKS_TA_H */

