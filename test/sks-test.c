/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <pkcs11.h>

#define CK2STR_ENTRY(label)	{ .id = label, .string = #label }

struct ck2str {
	CK_ULONG id;
	const char *string;
};

static struct ck2str ckr2str_table[] = {
	CK2STR_ENTRY(CKR_OK),
	CK2STR_ENTRY(CKR_CANCEL),
	CK2STR_ENTRY(CKR_HOST_MEMORY),
	CK2STR_ENTRY(CKR_SLOT_ID_INVALID),
	CK2STR_ENTRY(CKR_GENERAL_ERROR),
	CK2STR_ENTRY(CKR_FUNCTION_FAILED),
	CK2STR_ENTRY(CKR_ARGUMENTS_BAD),
	CK2STR_ENTRY(CKR_NO_EVENT),
	CK2STR_ENTRY(CKR_NEED_TO_CREATE_THREADS),
	CK2STR_ENTRY(CKR_CANT_LOCK),
	CK2STR_ENTRY(CKR_ATTRIBUTE_READ_ONLY),
	CK2STR_ENTRY(CKR_ATTRIBUTE_SENSITIVE),
	CK2STR_ENTRY(CKR_ATTRIBUTE_TYPE_INVALID),
	CK2STR_ENTRY(CKR_ATTRIBUTE_VALUE_INVALID),
	CK2STR_ENTRY(CKR_ACTION_PROHIBITED),
	CK2STR_ENTRY(CKR_DATA_INVALID),
	CK2STR_ENTRY(CKR_DATA_LEN_RANGE),
	CK2STR_ENTRY(CKR_DEVICE_ERROR),
	CK2STR_ENTRY(CKR_DEVICE_MEMORY),
	CK2STR_ENTRY(CKR_DEVICE_REMOVED),
	CK2STR_ENTRY(CKR_ENCRYPTED_DATA_INVALID),
	CK2STR_ENTRY(CKR_ENCRYPTED_DATA_LEN_RANGE),
	CK2STR_ENTRY(CKR_FUNCTION_CANCELED),
	CK2STR_ENTRY(CKR_FUNCTION_NOT_PARALLEL),
	CK2STR_ENTRY(CKR_FUNCTION_NOT_SUPPORTED),
	CK2STR_ENTRY(CKR_KEY_HANDLE_INVALID),
	CK2STR_ENTRY(CKR_KEY_SIZE_RANGE),
	CK2STR_ENTRY(CKR_KEY_TYPE_INCONSISTENT),
	CK2STR_ENTRY(CKR_KEY_NOT_NEEDED),
	CK2STR_ENTRY(CKR_KEY_CHANGED),
	CK2STR_ENTRY(CKR_KEY_NEEDED),
	CK2STR_ENTRY(CKR_KEY_INDIGESTIBLE),
	CK2STR_ENTRY(CKR_KEY_FUNCTION_NOT_PERMITTED),
	CK2STR_ENTRY(CKR_KEY_NOT_WRAPPABLE),
	CK2STR_ENTRY(CKR_KEY_UNEXTRACTABLE),
	CK2STR_ENTRY(CKR_MECHANISM_INVALID),
	CK2STR_ENTRY(CKR_MECHANISM_PARAM_INVALID),
	CK2STR_ENTRY(CKR_OBJECT_HANDLE_INVALID),
	CK2STR_ENTRY(CKR_OPERATION_ACTIVE),
	CK2STR_ENTRY(CKR_OPERATION_NOT_INITIALIZED),
	CK2STR_ENTRY(CKR_PIN_INCORRECT),
	CK2STR_ENTRY(CKR_PIN_INVALID),
	CK2STR_ENTRY(CKR_PIN_LEN_RANGE),
	CK2STR_ENTRY(CKR_PIN_EXPIRED),
	CK2STR_ENTRY(CKR_PIN_LOCKED),
	CK2STR_ENTRY(CKR_SESSION_CLOSED),
	CK2STR_ENTRY(CKR_SESSION_COUNT),
	CK2STR_ENTRY(CKR_SESSION_HANDLE_INVALID),
	CK2STR_ENTRY(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
	CK2STR_ENTRY(CKR_SESSION_READ_ONLY),
	CK2STR_ENTRY(CKR_SESSION_EXISTS),
	CK2STR_ENTRY(CKR_SESSION_READ_ONLY_EXISTS),
	CK2STR_ENTRY(CKR_SESSION_READ_WRITE_SO_EXISTS),
	CK2STR_ENTRY(CKR_SIGNATURE_INVALID),
	CK2STR_ENTRY(CKR_SIGNATURE_LEN_RANGE),
	CK2STR_ENTRY(CKR_TEMPLATE_INCOMPLETE),
	CK2STR_ENTRY(CKR_TEMPLATE_INCONSISTENT),
	CK2STR_ENTRY(CKR_TOKEN_NOT_PRESENT),
	CK2STR_ENTRY(CKR_TOKEN_NOT_RECOGNIZED),
	CK2STR_ENTRY(CKR_TOKEN_WRITE_PROTECTED),
	CK2STR_ENTRY(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
	CK2STR_ENTRY(CKR_UNWRAPPING_KEY_SIZE_RANGE),
	CK2STR_ENTRY(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
	CK2STR_ENTRY(CKR_USER_ALREADY_LOGGED_IN),
	CK2STR_ENTRY(CKR_USER_NOT_LOGGED_IN),
	CK2STR_ENTRY(CKR_USER_PIN_NOT_INITIALIZED),
	CK2STR_ENTRY(CKR_USER_TYPE_INVALID),
	CK2STR_ENTRY(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	CK2STR_ENTRY(CKR_USER_TOO_MANY_TYPES),
	CK2STR_ENTRY(CKR_WRAPPED_KEY_INVALID),
	CK2STR_ENTRY(CKR_WRAPPED_KEY_LEN_RANGE),
	CK2STR_ENTRY(CKR_WRAPPING_KEY_HANDLE_INVALID),
	CK2STR_ENTRY(CKR_WRAPPING_KEY_SIZE_RANGE),
	CK2STR_ENTRY(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
	CK2STR_ENTRY(CKR_RANDOM_SEED_NOT_SUPPORTED),
	CK2STR_ENTRY(CKR_RANDOM_NO_RNG),
	CK2STR_ENTRY(CKR_DOMAIN_PARAMS_INVALID),
	CK2STR_ENTRY(CKR_CURVE_NOT_SUPPORTED),
	CK2STR_ENTRY(CKR_BUFFER_TOO_SMALL),
	CK2STR_ENTRY(CKR_SAVED_STATE_INVALID),
	CK2STR_ENTRY(CKR_INFORMATION_SENSITIVE),
	CK2STR_ENTRY(CKR_STATE_UNSAVEABLE),
	CK2STR_ENTRY(CKR_CRYPTOKI_NOT_INITIALIZED),
	CK2STR_ENTRY(CKR_CRYPTOKI_ALREADY_INITIALIZED),
	CK2STR_ENTRY(CKR_MUTEX_BAD),
	CK2STR_ENTRY(CKR_MUTEX_NOT_LOCKED),
	CK2STR_ENTRY(CKR_NEW_PIN_MODE),
	CK2STR_ENTRY(CKR_NEXT_OTP),
	CK2STR_ENTRY(CKR_EXCEEDED_MAX_ITERATIONS),
	CK2STR_ENTRY(CKR_FIPS_SELF_TEST_FAILED),
	CK2STR_ENTRY(CKR_LIBRARY_LOAD_FAILED),
	CK2STR_ENTRY(CKR_PIN_TOO_WEAK),
	CK2STR_ENTRY(CKR_PUBLIC_KEY_INVALID),
	CK2STR_ENTRY(CKR_FUNCTION_REJECTED),
	CK2STR_ENTRY(CKR_VENDOR_DEFINED),
};

const char *ckr2str(CK_RV rv);

const char *ckr2str(CK_RV rv)
{
	static const char vendor[] = "(vendor-defined)";
	static const char unknown[] = "(unknown)";
	const int count = sizeof(ckr2str_table) / sizeof(struct ck2str);
	int n;

	for (n = 0; n < count; n++) {
		if (rv == ckr2str_table[n].id)
			return ckr2str_table[n].string;
	}

	if (rv >= CKR_VENDOR_DEFINED)
		return vendor;

	return unknown;
}

/* FIXME: This is an ugly print out of utf8 into ascci */
static void print_padded_string(char *prefix, void *data, size_t src_len)
{
	char *src = data;
	char *end = (char *)src + src_len;

	printf("%s\"", prefix);

	while (src < end)
		printf("%c", *src++);

	printf("\"\n");
}

static int print_library_info(CK_INFO *info)
{
	printf(",--- Library info -----------\n");
	printf("| Cryptoki version     : %d.%d\n",
		info->cryptokiVersion.major, info->cryptokiVersion.minor);
	print_padded_string("| Manufacturer Id      : ",
		info->manufacturerID, sizeof(info->manufacturerID));
	printf("| Flags                : %lx\n", info->flags);
	print_padded_string("| Library description  : ",
		info->libraryDescription, sizeof(info->libraryDescription));
	printf("| SKS library version  : %d.%d\n",
		info->libraryVersion.major, info->libraryVersion.minor);
	printf("`------------------------------\n");

	return 0;
}

static int print_token_info(CK_TOKEN_INFO *ck)
{
	printf(",--- Token info --------\n");

	print_padded_string("| label                : ",
			    ck->label, sizeof(ck->label));
	print_padded_string("| manufacturer         : ",
			    ck->manufacturerID, sizeof(ck->manufacturerID));
	print_padded_string("| model                : ",
			    ck->model, sizeof(ck->model));
	print_padded_string("| serial number        : ",
			    ck->serialNumber, sizeof(ck->serialNumber));

	printf("| flags                : 0x%lx\n", ck->flags);
	printf("| max session count    : 0x%lx\n", ck->ulMaxSessionCount);
	printf("| sessoin count        : 0x%lx\n", ck->ulSessionCount);
	printf("| max RW session count : 0x%lx\n", ck->ulMaxRwSessionCount);
	printf("| RW session count     : 0x%lx\n", ck->ulRwSessionCount);
	printf("| max pin length       : 0x%lx\n", ck->ulMaxPinLen);
	printf("| min pin len          : 0x%lx\n", ck->ulMinPinLen);
	printf("| total public memory  : 0x%lx\n", ck->ulTotalPublicMemory);
	printf("| free public memory   : 0x%lx\n", ck->ulFreePublicMemory);
	printf("| total private memory : 0x%lx\n", ck->ulTotalPrivateMemory);
	printf("| free private memory  : 0x%lx\n", ck->ulFreePrivateMemory);

	printf("| hardware version     : %u.%u\n",
		ck->hardwareVersion.major, ck->hardwareVersion.minor);
	printf("| firmware version     : %u.%u\n",
		ck->firmwareVersion.major, ck->firmwareVersion.minor);

	print_padded_string("| UTC time             : ",
			    ck->utcTime, sizeof(ck->utcTime));

	printf("`------------------------\n");
	return 0;
}

static int print_mecha_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *ck)
{
	printf(",--- Mechanism info --------\n");
	printf("| type 0x%08lx - min/max key size %lu/%lu - flags 0x%lx\n",
		type, ck->ulMinKeySize, ck->ulMaxKeySize, ck->flags);
	printf("`------------------------\n");

	return 0;
}

int test_token_basics(void)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slot_ids;
	CK_ULONG slot_count;
	CK_ULONG slot_count2;
	CK_INFO lib_info;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	size_t i;
	size_t j;

	rv = C_Initialize(NULL);
	if (rv)
		err(1, "C_Initialize failed %lx (%s)\n", rv, ckr2str(rv));

	printf("SKS TA - Cryptoki state\n");

	rv = C_GetInfo(&lib_info);
	if (rv)
		err(-1, "C_GetInfo failed %lx (%s)\n", rv, ckr2str(rv));

	print_library_info(&lib_info);

	rv = C_GetFunctionList(NULL);
	if (rv)
		printf("- C_GetFunctionList\t\trv=%lx (%s)\n", rv, ckr2str(rv));
	else
		printf("- function list found: TODO\n");

	slot_count2 = 0;
	rv = C_GetSlotList(0, NULL, &slot_count2);
	if (rv != CKR_BUFFER_TOO_SMALL)
		err(1, "C_GetSlotList failed %lx (%s)\n", rv, ckr2str(rv));

	slot_count = 0;
	rv = C_GetSlotList(1, NULL, &slot_count);
	if (rv != CKR_BUFFER_TOO_SMALL)
		err(1, "C_GetSlotList failed %lx (%s)\n", rv, ckr2str(rv));

	slot_ids = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (slot_count && !slot_ids)
		errx(1, "out of memory\n");

	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (rv)
		err(1, "C_GetSlotList failed %lx (%s)\n", rv, ckr2str(rv));

	printf("- %lu slots found, %lu slots with present token\n",
			slot_count2, slot_count);

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = *(slot_ids + i);
		CK_MECHANISM_TYPE_PTR mecha_types;
		CK_ULONG mecha_count;

		rv = C_GetSlotInfo(slot, &slot_info);
		if (rv)
			err(1, "C_GetSlotInfo failed %lx (%s)\n", rv, ckr2str(rv));

		printf("| slot #%lu info: TODO\n", slot);

		rv = C_GetTokenInfo(slot, &token_info);
		if (rv)
			err(1, "C_GetTokenInfo failed %lx (%s)\n", rv, ckr2str(rv));

		print_token_info(&token_info);

		mecha_count = 0;
		rv = C_GetMechanismList(slot, NULL, &mecha_count);
		if (rv != CKR_BUFFER_TOO_SMALL)
			err(1, "C_GetMechanismList failed %lx (%s)\n", rv, ckr2str(rv));

		mecha_types = calloc(mecha_count, sizeof(CK_MECHANISM_TYPE));
		if (mecha_count && !mecha_types)
			errx(1, "out of memory\n");

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (rv)
			err(1, "C_GetMechanismList failed %lx (%s)\n", rv, ckr2str(rv));

		printf("| Token lists %lu mechanism%s\n",
				mecha_count, mecha_count ? "" : "s");

		for (j = 0; j < mecha_count; j++) {
			CK_MECHANISM_TYPE type = *(mecha_types + j);
			CK_MECHANISM_INFO mecha_info;

			rv = C_GetMechanismInfo(slot, type, &mecha_info);
			if (rv)
				err(1, "C_GetMechanismInfo failed %lx (%s)\n", rv, ckr2str(rv));

			print_mecha_info(type, &mecha_info);
		}
	}

	rv = C_Finalize(NULL);
	if (rv)
		err(1, "C_Finalize failed %lx (%s)\n", rv, ckr2str(rv));

	return 0;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int rc;

	rc = test_token_basics();
	if (rc)
		return rc;

	return 0;
}
