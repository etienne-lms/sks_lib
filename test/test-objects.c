/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <pkcs11.h>
#include <sks_ck_debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ATTR_COUNT(attr)	(sizeof(attr) / sizeof(CK_ATTRIBUTE))

static CK_OBJECT_CLASS cktest_symkeyClass = CKO_SECRET_KEY;

static CK_KEY_TYPE cktest_aes_keyType = CKK_AES;

static CK_BYTE cktest_aes_KeyValue1[] =
	{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

static CK_BBOOL cktest_true = CK_TRUE;
static CK_BBOOL cktest_false = CK_FALSE;

CK_ATTRIBUTE cktest_aes_cipher_keyTemplate[] = {
	{ CKA_ENCRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_true, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

CK_ATTRIBUTE cktest_aes_encrypt_keyTemplate[] = {
	{ CKA_ENCRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

CK_ATTRIBUTE cktest_aes_decrypt_keyTemplate[] = {
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_false, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};



static char iv[16] = { 0 };

CK_MECHANISM cktest_aes_cbc_mechanism = { CKM_AES_CBC, iv, sizeof(iv) };

CK_RV cktest_create_objects(void);
CK_RV cktest_create_objects(void)
{
	CK_RV rv;
	CK_SLOT_ID slots[10];
	CK_ULONG count;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE aes_cipher_keyhld;
	CK_OBJECT_HANDLE aes_encrypt_keyhld;
	CK_OBJECT_HANDLE aes_decrypt_keyhld;
	CK_BYTE *in, *full_in, *out, *full_out;
	CK_ULONG in_len, out_len, full_len;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	count = 10;
	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv)
		return rv;

	if (!count || count > 10) {
		printf("Error: C_GetSlotList: bad slot count %lu\n", count);
		rv = CKR_GENERAL_ERROR;
		goto bail_lib;
	}

	/*
	 * Test #1: open a session, import an AES encryption/decryption key
	 *	    and run an encryption.
	 */
	printf("Test AES key creation for encryption/decryption\n");

	rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, 0, &session);
	if (rv) {
		printf("Error: C_OpenSession: 0x%lx\n", rv);
		goto bail_lib;
	}

	rv = C_CreateObject(session, cktest_aes_cipher_keyTemplate,
			    ATTR_COUNT(cktest_aes_cipher_keyTemplate),
			    &aes_cipher_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: 0x%lx\n", rv);
		goto bail_session;
	}

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism,
			   aes_cipher_keyhld);
	if (rv) {
		printf("Error: C_EncryptInit: 0x%lx\n", rv);
		goto bail_session;
	}

	/* Run an AES ciphering in 3 C_EncryptUpdate() steps */
	full_len = 1024 + 10000 + 100000;
	full_in = malloc(full_len);
	full_out = malloc(full_len);
	if (!full_in || !full_out)
		err(-1, "out-of-memory\n");
	in = full_in;
	out = full_out;

	in_len = 1024;
	out_len = 1024;

	rv = C_EncryptUpdate(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptUpdate: 0x%lx\n", rv);
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	in_len = 10000;
	out_len = 10000;

	rv = C_EncryptUpdate(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptUpdate: 0x%lx\n", rv);
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	in_len = 10000;
	out_len = 10000;

	rv = C_EncryptUpdate(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptUpdate: 0x%lx\n", rv);
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	out_len = 0;

	rv = C_EncryptFinal(session, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptFinal: 0x%lx\n", rv);
		goto bail_session;
	}

	printf("  => Test OK\n");

	/*
	 * Test #2: from the same pkcs11 session,  import a decryption only
	 *	    key and run a encryption. Should succeed.
	 */
	printf("Test AES encryption with an AES encryption only key\n");

	rv = C_CreateObject(session, cktest_aes_decrypt_keyTemplate,
			    ATTR_COUNT(cktest_aes_decrypt_keyTemplate),
			    &aes_decrypt_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: 0x%lx\n", rv);
		goto bail_session;
	}

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism,
			   aes_decrypt_keyhld);
	if (rv == CKR_OK) {
		printf("Error: C_EncryptInit expected to fail but did not!\n");
		goto bail_session;
	}

	printf("  => Test OK\n");

	/*
	 * Test #3: from the same pkcs11 session, import a encryption only
	 *	    key and run an encryption. Should succeed even if previous
	 *	    encryption init failed.
	 */
	printf("Test AES encrypt with valid key over the same session\n");

	rv = C_CreateObject(session, cktest_aes_encrypt_keyTemplate,
			    ATTR_COUNT(cktest_aes_encrypt_keyTemplate),
			    &aes_encrypt_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: 0x%lx\n", rv);
		goto bail_session;
	}

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism,
			   aes_encrypt_keyhld);
	if (rv) {
		printf("Error: C_EncryptInit: 0x%lx\n", rv);
		goto bail_session;
	}

	in = full_in;
	out = full_out;
	in_len = full_len;
	out_len = full_len;

	rv = C_Encrypt(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_Encrypt: 0x%lx\n", rv);
		goto bail_session;
	}

	printf("  => Test OK\n");

bail_session:
	rv = C_CloseSession(session);
	if (rv) {
		printf("Error: C_CloseSession: 0x%lx\n", rv);
		return rv;
	}

bail_lib:
	rv = C_Finalize(0);
	if (rv)
		printf("Error: C_Finalize: 0x%lx\n", rv);

	return rv;
}