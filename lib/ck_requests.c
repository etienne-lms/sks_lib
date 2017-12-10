/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_ta.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include "ck_requests.h"
#include "invoke_ta.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "serialize_ck.h"

static struct sks_invoke *ck_session2sks_ctx(CK_SESSION_HANDLE session)
{
	(void)session;
	// TODO: find back the invocation context from the session handle
	// Until we do that, let's use the default invacation context.
	return NULL;
}

CK_RV ck_create_object(CK_SESSION_HANDLE session,
			CK_ATTRIBUTE_PTR attribs,
			CK_ULONG count,
			CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;
	struct serializer obj;
	char *ctrl = NULL;
	size_t ctrl_size;
	uint32_t key_handle;
	uint32_t session_handle = session;
	size_t key_handle_size = sizeof(key_handle);

	rv = serialize_ck_attributes(&obj, attribs, count);
	if (rv)
		goto out;

	/* ctrl = [session-handle][raw-head][serialized-attributes] */
	ctrl_size = sizeof(uint32_t) + get_serial_object_size(&obj);
	ctrl = malloc(ctrl_size);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	memcpy(ctrl, &session_handle, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), get_serial_object_buffer(&obj),
					get_serial_object_size(&obj));

	release_serial_object(&obj);

	rv = sks_invoke_ta(ck_session2sks_ctx(session),
			   SKS_CMD_CK_CREATE_OBJECT, ctrl, ctrl_size,
			   NULL, 0, &key_handle, &key_handle_size);
	if (rv)
		goto out;

	*phObject = key_handle;

out:
	free(ctrl);
	return rv;
}

CK_RV ck_encdecrypt_init(CK_SESSION_HANDLE session,
		    CK_MECHANISM_PTR mechanism,
		    CK_OBJECT_HANDLE key,
		    int decrypt)
{
	CK_RV rv;
	struct serializer obj;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	char *ctrl = NULL;
	size_t ctrl_size;

	rv = serialize_ck_mecha_params(&obj, mechanism);
	if (rv)
		return rv;

	/* params = [session-handle][key-handle][serialized-mechanism-blob] */
	ctrl_size = 2 * sizeof(uint32_t) + obj.size;
	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &session_handle, sizeof(session_handle));
	memcpy(ctrl + sizeof(uint32_t), &key_handle, sizeof(key_handle));
	memcpy(ctrl + 2 * sizeof(uint32_t), obj.buffer, obj.size);

	rv = sks_invoke_ta(ck_session2sks_ctx(session),
			   decrypt ? SKS_CMD_CK_DECRYPT_INIT :
			   SKS_CMD_CK_ENCRYPT_INIT,
			   ctrl, ctrl_size, NULL, 0, NULL, NULL);

	/* Specific return value to handle ?*/
	free(ctrl);
	return rv;
}

CK_RV ck_encdecrypt_update(CK_SESSION_HANDLE session,
			   CK_BYTE_PTR in,
			   CK_ULONG in_len,
			   CK_BYTE_PTR out,
			   CK_ULONG_PTR out_len,
			   int decrypt)
{
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *in_buf = in;
	size_t in_size = in_len;
	void *out_buf = out;
	size_t out_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	if (!out_len)
		out_size = 0;
	else
		out_size = *out_len;

	rv = sks_invoke_ta(ck_session2sks_ctx(session),
			   decrypt ? SKS_CMD_CK_DECRYPT_UPDATE :
			   SKS_CMD_CK_ENCRYPT_UPDATE,
			   &ctrl, ctrl_size, in_buf, in_size, out_buf, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL && out_len))
		*out_len = out_size;

	return rv;
}

CK_RV ck_encdecrypt_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len,
			  int decrypt)
{
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *out_buf = out;
	size_t out_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	if (!out_len)
		out_size = 0;
	else
		out_size = *out_len;

	rv = sks_invoke_ta(ck_session2sks_ctx(session),
			   decrypt ? SKS_CMD_CK_DECRYPT_FINAL :
			   SKS_CMD_CK_ENCRYPT_FINAL,
			   &ctrl, ctrl_size, NULL, 0, out_buf, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	return rv;
}
