/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <sks_abi.h>
#include <sks_ta.h>
#include <stdlib.h>
#include <string.h>

#include "handle.h"
#include "helpers_ck.h"
#include "invoke_ta.h"
#include "local_utils.h"
#include "pkcs11_token.h"

static struct handle_db handle_db = HANDLE_DB_INITIALIZER;

/*
 * Currently assume the TEE provides only 1 slot.
 * In the future, the PKCS11 TA may support several slots
 */
#define SKS_CK_SLOT_ID		0x0

static int slot_is_valid(CK_SLOT_ID slot)
{
	/* Only 1 slot is considered (TODO: invoke the TA to get the count) */
	return (slot == SKS_CK_SLOT_ID);
}

#define SKS_CRYPTOKI_SLOT_DESCRIPTION		"OP-TEE SKS"
#define SKS_CRYPTOKI_SLOT_MANUFACTURER		"Linaro"
#define SKS_CRYPTOKI_SLOT_HW_VERSION		{ .major = 0, .minor = 0 }
#define SKS_CRYPTOKI_SLOT_FW_VERSION		{ .major = 0, .minor = 0 }

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		memset((char *)_dst, ' ', sizeof(_dst)); \
		strncpy((char *)_dst, _src, sizeof(_dst)); \
	} while (0)

/**
 * sks_ck_get_info - implementation of C_GetInfo
 */
int sks_ck_get_info(CK_INFO_PTR info)
{
	const CK_VERSION ck_version = { 2, 40 };
	const char manuf_id[] = SKS_CRYPTOKI_SLOT_MANUFACTURER; // TODO slot?
	const CK_FLAGS flags = 0;	/* must be zero per the PKCS#11 2.40 */
	const char lib_description[] = "OP-TEE SKS Cryptoki library";
	const CK_VERSION lib_version = { 0, 0 };

	info->cryptokiVersion = ck_version;
	PADDED_STRING_COPY(info->manufacturerID, manuf_id);
	info->flags = flags;
	PADDED_STRING_COPY(info->libraryDescription, lib_description);
	info->libraryVersion = lib_version;

	return CKR_OK;
}

/**
 * slot_get_info - implementation of C_GetSlotList
 */
CK_RV sks_ck_slot_get_list(CK_BBOOL present,
			   CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	if (*count < 1) {
		*count = 1;
		return CKR_BUFFER_TOO_SMALL;
	}

	if (present && sks_invoke_ta(NULL, SKS_CMD_CK_PING,
				     NULL, 0, NULL, 0, NULL, NULL)) {
		*count = 0;
		return CKR_OK;
	}

	*count = 1;
	*slots = SKS_CK_SLOT_ID;

	return CKR_OK;
}

/**
 * slot_get_info - implementation of C_GetSlotInfo
 */
int sks_ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	const char desc[] = SKS_CRYPTOKI_SLOT_DESCRIPTION;
	const char manuf[] = SKS_CRYPTOKI_SLOT_MANUFACTURER;
	const CK_VERSION hwver = SKS_CRYPTOKI_SLOT_HW_VERSION;
	const CK_VERSION fwver = SKS_CRYPTOKI_SLOT_FW_VERSION;

	if (!slot_is_valid(slot))
		return CKR_SLOT_ID_INVALID;

	PADDED_STRING_COPY(info->slotDescription, desc);
	PADDED_STRING_COPY(info->manufacturerID, manuf);

	/*
	 * CKF_TOKEN_PRESENT a token is there: ping it!
	 * CKF_REMOVABLE_DEVICE removable device²? if TA goes away...
	 * CKF_HW_SLOT hardware slot ? tz is a hw or sw slot?
	 */
	info->flags = 0;
	if (sks_invoke_ta(NULL, SKS_CMD_CK_PING, NULL, 0, NULL, 0, NULL, NULL))
		info->flags |= CKF_TOKEN_PRESENT;

	info->hardwareVersion = hwver;
	info->firmwareVersion = fwver;

	return CKR_OK;
}

/**
 * slot_get_info - implementation of C_GetTokenInfo
 */
CK_RV sks_ck_token_get_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_TOKEN_INFO *ck_info = info;
	TEEC_SharedMemory *shm;
	size_t size = 0;
	CK_RV rv = CKR_GENERAL_ERROR;

	if (!slot_is_valid(slot))
		return CKR_SLOT_ID_INVALID;

	if (sks_invoke_ta(NULL, SKS_CMD_CK_TOKEN_INFO, NULL, 0,
			  NULL, 0, NULL, &size) != CKR_BUFFER_TOO_SMALL)
		return CKR_DEVICE_ERROR;

	shm = sks_alloc_shm_out(NULL, size);
	if (!shm)
		return CKR_HOST_MEMORY;

	if (sks_invoke_ta(NULL, SKS_CMD_CK_TOKEN_INFO,
			  NULL, 0, NULL, 0, shm, NULL) != CKR_OK) {
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	if (shm->size < sizeof(struct sks_ck_token_info)) {
		LOG_ERROR("unexpected bad token info size\n");
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	if (sks2ck_token_info(ck_info, shm->buffer)) {
		LOG_ERROR("unexpected bad token info structure\n");
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	rv = CKR_OK;
bail:
	sks_free_shm(shm);
	return rv;
}

/*
 * TODO
 */
CK_RV sks_ck_token_mechanism_ids(CK_SLOT_ID slot,
				 CK_MECHANISM_TYPE_PTR mechanisms,
				 CK_ULONG_PTR count)
{
	uint32_t outsize = *count * sizeof(uint32_t);
	void *outbuf;
	CK_RV rv;

	if (!slot_is_valid(slot))
		return CKR_SLOT_ID_INVALID;

	outbuf = malloc(outsize);
	if (!outbuf)
		return CKR_HOST_MEMORY;

	rv = sks_invoke_ta(NULL, SKS_CMD_CK_MECHANISM_IDS, NULL, 0, NULL, 0,
							   outbuf, &outsize);
	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*count = outsize / sizeof(uint32_t);
	if (rv)
		goto bail;

	if (sks2ck_mechanism_type(mechanisms, outbuf, *count)) {
		LOG_ERROR("unexpected bad mechanism_type list\n");
		rv = CKR_DEVICE_ERROR;
	}

bail:
	free(outbuf);

	return rv;
}

/* CK_MECHANISM_INFO = 3 ulong = 3 * 32bit in SKS */
CK_RV sks_ck_token_mechanism_info(CK_SLOT_ID slot,
				  CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR info)
{
	CK_RV rv;
	uint32_t outbuf[3];
	uint32_t outsize = sizeof(outbuf);
	uint32_t sks_type = type;

	if (!slot_is_valid(slot))
		return CKR_SLOT_ID_INVALID;

	/* info is large enought, for shure */
	rv = sks_invoke_ta(NULL, SKS_CMD_CK_MECHANISM_INFO,
			   &sks_type, sizeof(uint32_t), NULL, 0, outbuf, &outsize);

	if (rv || outsize != sizeof(outbuf)) {
		LOG_ERROR("unexpected bad state\n");
		return CKR_DEVICE_ERROR;
	}

	if (sks2ck_mechanism_info(info, outbuf)) {
		LOG_ERROR("unexpected bad mechanism info structure\n");
		rv = CKR_DEVICE_ERROR;
	}
	return rv;
}

/*
 * TODO: with following code, the session identifier are abstracted by the SKS
 * library. It could be better to let the TA provide the handle, so that
 * several applications can see the same session identifiers.
 */
CK_RV sks_ck_open_session(CK_SLOT_ID slot,
		          CK_FLAGS flags,
		          CK_VOID_PTR cookie,
		          CK_NOTIFY callback,
		          CK_SESSION_HANDLE_PTR session)
{
	struct sks_ck_session *sess;
	size_t out_sz = sizeof(sess->handle);
	unsigned long cmd;
	int handle;
	CK_RV rv;

	if (cookie || callback) {
		LOG_ERROR("C_OpenSession does not handle callback yet\n");
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (!slot_is_valid(slot))
		return CKR_SLOT_ID_INVALID;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return CKR_HOST_MEMORY;

	sess->slot = slot;

	if (flags & CKF_RW_SESSION)
		cmd = SKS_CMD_CK_OPEN_RW_SESSION;
	else
		cmd = SKS_CMD_CK_OPEN_RO_SESSION;

	rv = sks_invoke_ta(&sess->ctx, cmd, NULL, 0, NULL, 0,
			   &sess->handle, &out_sz);
	if (rv != CKR_OK)
		goto device_error;

	handle = handle_get(&handle_db, sess);
	*session = handle;

	return CKR_OK;

device_error:
	free(sess);
	return rv;
}

CK_RV sks_ck_close_session(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	int handle = (int)session;
	struct sks_ck_session *sess = handle_lookup(&handle_db, handle);
	uint32_t ctrl;
	size_t ctrl_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	rv = sks_invoke_ta(&sess->ctx, SKS_CMD_CK_CLOSE_SESSION,
			   &ctrl, ctrl_size, NULL, 0, NULL, NULL);
	if (rv != CKR_OK)
		return rv;

	sess = handle_put(&handle_db, handle);
	free(sess);

	return CKR_OK;
}

/*
 * Scan all registered session handle by the lib
 * and close all session related to the target slot.
 */
CK_RV sks_ck_close_all_sessions(CK_SLOT_ID slot)
{
	int handle = handle_next(&handle_db, -1);

	while (handle >= 0) {
		struct sks_ck_session *sess = handle_lookup(&handle_db, handle);
		CK_SESSION_HANDLE session = sess ? sess->handle : 0;

		if (sess && sess->slot == slot)
			sks_ck_close_session(session);

		handle = handle_next(&handle_db, handle);
	}

	return CKR_OK;
}

CK_RV sks_ck_get_session_info(CK_SESSION_HANDLE session,
			      CK_SESSION_INFO_PTR info)
{
	CK_RV rv;
	int handle = (int)session;
	struct sks_ck_session *sess = handle_lookup(&handle_db, handle);
	uint32_t ctrl;
	size_t ctrl_size;
	size_t info_size;

	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	/* out = [session-info] */
	info_size = sizeof(CK_SESSION_INFO);

	return sks_invoke_ta(&sess->ctx, SKS_CMD_CK_SESSION_INFO,
			     &ctrl, ctrl_size, NULL, 0, info, &info_size);
}
