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

static CK_ATTRIBUTE cktest_aes_cipher_keyTemplate[] = {
	{ CKA_ENCRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_true, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

static CK_ATTRIBUTE cktest_aes_encrypt_keyTemplate[] = {
	{ CKA_ENCRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

static CK_ATTRIBUTE cktest_aes_decrypt_keyTemplate[] = {
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_false, sizeof(cktest_true) },
	{ CKA_COPYABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_MODIFIABLE, &cktest_false, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};



static char iv[16] = { 0 };

static CK_MECHANISM cktest_aes_cbc_mechanism = { CKM_AES_CBC, iv, sizeof(iv) };

static CK_RV close_lib(void)
{
	CK_RV rv;

	rv = C_Finalize(0);
	if (rv)
		printf("Error: C_Finalize: %lx (%s)\n", rv, ckr2str(rv));

	return rv;
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots;
	CK_ULONG count;

	rv = C_Initialize(0);
	if (rv) {
		printf("C_Initialize failed, %s\n", ckr2str(rv));
		return rv;
	}

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		printf("C_GetSlotList failed, %s\n", ckr2str(rv));
		goto bail;
	}

	if (count < 1) {
		printf("No slot with presetn token found. Abort test\n");
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		printf("Error: out of memory, %lu slots found\n", count);
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv) {
		printf("C_GetSlotList failed, %s\n", ckr2str(rv));
		goto bail;
	}

	/* Use the 1st slot */
	*slot = *slots;

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

static CK_RV cktest_basic_aes_ciphering(void)
{
	CK_RV rv;
	CK_RV rv2;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE aes_cipher_keyhld;
	CK_OBJECT_HANDLE aes_encrypt_keyhld;
	CK_OBJECT_HANDLE aes_decrypt_keyhld;
	CK_BYTE *in, *full_in, *out, *full_out;
	CK_ULONG in_len, out_len, full_len;

	printf("Test AES key creation and AES operations\n");

	rv = init_lib_and_find_token_slot(&slot);
	if (rv)
		return rv;

	/*
	 * Test #1: open a session, import an AES encryption/decryption key
	 *	    and run an encryption.
	 */
	printf(" - Test AES key creation for encryption/decryption\n");

	rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
			   NULL, 0, &session);
	if (rv) {
		printf("Error: C_OpenSession: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_lib;
	}

	rv = C_CreateObject(session, cktest_aes_cipher_keyTemplate,
			    ATTR_COUNT(cktest_aes_cipher_keyTemplate),
			    &aes_cipher_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism,
			   aes_cipher_keyhld);
	if (rv) {
		printf("Error: C_EncryptInit: %lx (%s)\n", rv, ckr2str(rv));
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
		printf("Error: C_EncryptUpdate: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	in_len = 10000;
	out_len = 10000;

	rv = C_EncryptUpdate(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptUpdate: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	in_len = 10000;
	out_len = 10000;

	rv = C_EncryptUpdate(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptUpdate: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	in += in_len;
	out += out_len;
	out_len = 0;

	rv = C_EncryptFinal(session, out, &out_len);
	if (rv) {
		printf("Error: C_EncryptFinal: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	printf("  => Test OK\n");

	/*
	 * Test #2: from the same pkcs11 session,  import a decryption only
	 *	    key and run a encryption. Should succeed.
	 */
	printf(" - Test AES encryption with an AES decryption only key\n");

	rv = C_CreateObject(session, cktest_aes_decrypt_keyTemplate,
			    ATTR_COUNT(cktest_aes_decrypt_keyTemplate),
			    &aes_decrypt_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: %lx (%s)\n", rv, ckr2str(rv));
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
	printf(" - Test AES encrypt with valid key over the same session\n");

	rv = C_CreateObject(session, cktest_aes_encrypt_keyTemplate,
			    ATTR_COUNT(cktest_aes_encrypt_keyTemplate),
			    &aes_encrypt_keyhld);
	if (rv) {
		printf("Error: C_CreateObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism,
			   aes_encrypt_keyhld);
	if (rv) {
		printf("Error: C_EncryptInit: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	in = full_in;
	out = full_out;
	in_len = full_len;
	out_len = full_len;

	rv = C_Encrypt(session, in, in_len, out, &out_len);
	if (rv) {
		printf("Error: C_Encrypt: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	rv = C_DestroyObject(session, aes_cipher_keyhld);
	if (rv) {
		printf("Error: C_DestroyObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

bail_session:
	rv2 = C_CloseSession(session);
	if (rv2)
		printf("Error: C_CloseSession: %lx (%s)\n", rv, ckr2str(rv2));
	if (rv == CKR_OK)
		rv = rv2;

bail_lib:
	rv2 = close_lib();
	if (rv == CKR_OK)
		rv = rv2;

	if (rv == CKR_OK)
		printf(" => test successful\n");

	return rv;
}

static CK_ATTRIBUTE cktest_token_object[] = {
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_true, sizeof(cktest_true) },
	{ CKA_MODIFIABLE, &cktest_true, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

static CK_ATTRIBUTE cktest_session_object[] = {
	{ CKA_DECRYPT,	&cktest_true, sizeof(cktest_true) },
	{ CKA_TOKEN,	&cktest_false, sizeof(cktest_true) },
	{ CKA_MODIFIABLE, &cktest_true, sizeof(cktest_false) },
	{ CKA_KEY_TYPE,	&cktest_aes_keyType, sizeof(cktest_aes_keyType) },
	{ CKA_CLASS,	&cktest_symkeyClass, sizeof(cktest_symkeyClass) },
	{ CKA_VALUE,	cktest_aes_KeyValue1, sizeof(cktest_aes_KeyValue1) }
};

/* Create session object and token object from a session */
static CK_RV cktest_create_objects_in_session(int readwrite)
{
	CK_RV rv;
	CK_RV rv2;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE token_obj_hld;
	CK_OBJECT_HANDLE session_obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	printf("Create session and token objects in a %s session\n",
		readwrite ? "read/write" : "read-only");

	rv = init_lib_and_find_token_slot(&slot);
	if (rv)
		return rv;

	if (readwrite)
		session_flags |= CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv) {
		printf("Error: C_OpenSession: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_lib;
	}

	rv = C_CreateObject(session, cktest_token_object,
			    ATTR_COUNT(cktest_token_object), &token_obj_hld);
	if ((readwrite && rv) ||
	    (!readwrite && rv != CKR_SESSION_READ_ONLY)) {
		printf("Error: C_CreateObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	rv = C_CreateObject(session, cktest_session_object,
			    ATTR_COUNT(cktest_session_object), &session_obj_hld);
	if (rv) {
		printf("Error: C_CreateObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	if (readwrite)
		rv = C_DestroyObject(session, token_obj_hld);
	if (rv) {
		printf("Error: C_DestroyObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

	rv = C_DestroyObject(session, session_obj_hld);
	if (rv) {
		printf("Error: C_DestroyObject: %lx (%s)\n", rv, ckr2str(rv));
		goto bail_session;
	}

bail_session:
	rv2 = C_CloseSession(session);
	if (rv2)
		printf("Error: C_CloseSession: %lx (%s)\n", rv, ckr2str(rv));
	if (rv == CKR_OK)
		rv = rv2;

bail_lib:
	rv2 = close_lib();
	if (rv == CKR_OK)
		rv = rv2;

	if (rv == CKR_OK)
		printf(" => test successful\n");

	return rv;
}


CK_RV cktest_create_objects(void);
CK_RV cktest_create_objects(void)
{
	CK_RV rv;

	/* Create object in a read/write session */
	rv = cktest_create_objects_in_session(1);
	if (rv)
		return rv;

	/* Create object in a read-only session */
	rv = cktest_create_objects_in_session(0);
	if (rv)
		return rv;

	rv = cktest_basic_aes_ciphering();
	if (rv)
		return rv;

	return rv;
}
