/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __CK_REQUEST_H
#define __CK_REQUEST_H

#include <pkcs11.h>

CK_RV ck_create_object(CK_SESSION_HANDLE session,
			CK_ATTRIBUTE_PTR attribs,
			CK_ULONG count,
			CK_OBJECT_HANDLE_PTR phObject);

CK_RV ck_encdecrypt_init(CK_SESSION_HANDLE session,
			 CK_MECHANISM_PTR mechanism,
			 CK_OBJECT_HANDLE key,
			 int decrypt);

CK_RV ck_encdecrypt_update(CK_SESSION_HANDLE session,
			   CK_BYTE_PTR in,
			   CK_ULONG in_len,
			   CK_BYTE_PTR out,
			   CK_ULONG_PTR out_len,
			   int decrypt);

CK_RV ck_encdecrypt_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len,
			  int decrypt);

#endif /*__CK_REQUEST_H*/
