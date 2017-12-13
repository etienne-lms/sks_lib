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

static int print_slot_info(CK_SLOT_INFO *ck)
{
	char *flagstr = ck_slot_flag2str(ck->flags);

	printf(",--- Slot info --------\n");

	print_padded_string("| description          : ",
			    ck->slotDescription, sizeof(ck->slotDescription));
	print_padded_string("| manufacturer         : ",
			    ck->manufacturerID, sizeof(ck->manufacturerID));

	printf("| flags                : 0x%lx\n", ck->flags);
	if (flagstr)
		printf("|     details on flags : %s\n", flagstr);

	printf("| hardware version     : %u.%u\n",
		ck->hardwareVersion.major, ck->hardwareVersion.minor);
	printf("| firmware version     : %u.%u\n",
		ck->firmwareVersion.major, ck->firmwareVersion.minor);

	printf("`------------------------\n");

	free(flagstr);
	return 0;
}

static int print_token_info(CK_TOKEN_INFO *ck)
{
	char *flagstr = ck_token_flag2str(ck->flags);

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
	if (flagstr)
		printf("|     details on flags : %s\n", flagstr);
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

	free(flagstr);
	return 0;
}

static int print_mecha_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *ck)
{
	char *flagstr = ck_mecha_flag2str(ck->flags);

	printf("| type %s - flags 0x%lx", ckm2str(type), ck->flags);

	switch (type) {
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_MAC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTR:
	case CKM_AES_GCM:
	case CKM_AES_CCM:
	case CKM_AES_CTS:
		printf(" - min/max key size %lu/%lu",
			ck->ulMinKeySize, ck->ulMaxKeySize);
		break;
	default:
		break;
	}

	if (flagstr)
		printf(" - flags set: %s", flagstr);

	printf("\n");

	free(flagstr);
	return 0;
}

static int test_token_basics(void)
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

	printf("SKS TA - test Cryptoki token info APIs\n");

	rv = C_Initialize(NULL);
	if (rv)
		err(1, "C_Initialize failed %lx (%s)\n", rv, ckr2str(rv));

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

		print_slot_info(&slot_info);


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

		printf("`------------------------\n");

	}

	rv = C_Finalize(NULL);
	if (rv)
		err(1, "C_Finalize failed %lx (%s)\n", rv, ckr2str(rv));

	printf(" => Test succeed\n");
	return 0;
}

CK_RV cktest_create_objects(void);

int test_aes_ciphering(void)
{
	CK_RV rv;

	rv = cktest_create_objects();

	return rv ? -1 : 0;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int rc;

	rc = test_token_basics();
	if (rc)
		return rc;

	rc = test_aes_ciphering();
	if (rc)
		return rc;

	return 0;
}
