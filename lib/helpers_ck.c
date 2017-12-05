/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "helpers_ck.h"
#include <string.h>

#define MEMCPY_FIELD(_dst, _src, _f) \
	do { \
		memcpy((_dst)->_f, (_src)->_f, sizeof((_dst)->_f)); \
		if (sizeof((_dst)->_f) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

#define MEMCPY_VERSION(_dst, _src, _f) \
	do { \
		memcpy(&(_dst)->_f, (_src)->_f, sizeof(CK_VERSION)); \
		if (sizeof(CK_VERSION) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)


CK_RV sks2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct sks_ck_token_info *sks_info)
{
	MEMCPY_FIELD(ck_info, sks_info, label);
	MEMCPY_FIELD(ck_info, sks_info, manufacturerID);
	MEMCPY_FIELD(ck_info, sks_info, model);
	MEMCPY_FIELD(ck_info, sks_info, serialNumber);
	ck_info->flags = sks_info->flags;
	ck_info->ulMaxSessionCount = sks_info->ulMaxSessionCount;
	ck_info->ulSessionCount = sks_info->ulSessionCount;
	ck_info->ulMaxRwSessionCount = sks_info->ulMaxRwSessionCount;
	ck_info->ulRwSessionCount = sks_info->ulRwSessionCount;
	ck_info->ulMaxPinLen = sks_info->ulMaxPinLen;
	ck_info->ulMinPinLen = sks_info->ulMinPinLen;
	ck_info->ulTotalPublicMemory = sks_info->ulTotalPublicMemory;
	ck_info->ulFreePublicMemory = sks_info->ulFreePublicMemory;
	ck_info->ulTotalPrivateMemory = sks_info->ulTotalPrivateMemory;
	ck_info->ulFreePrivateMemory = sks_info->ulFreePrivateMemory;
	MEMCPY_VERSION(ck_info, sks_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, sks_info, firmwareVersion);
	MEMCPY_FIELD(ck_info, sks_info, utcTime);

	return CKR_OK;
}

/*
 * Converts an array on sks ulongs into a array of CK ulongs.
 * Source and destination may not be 32bit aligned.
 */
CK_RV sks2ck_ulong_array(void *dst, void *src, size_t count)
{
	char *ck = dst;
	char *sks = src;
	const size_t spare = sizeof(CK_ULONG) - sizeof(uint32_t);

	/* Convert each 32bit into a CK ulong (32bit case => single memcpy() */
	while (count--) {
		uint32_t sksv;
		CK_ULONG ckv;
		CK_ULONG ckv2;

		/* Warning: matches 32bit and 64bit little-endian cases */
		memcpy(ck, sks, sizeof(uint32_t));
		memset(ck + sizeof(uint32_t), 0, spare);
		sks += sizeof(uint32_t);
		ck += sizeof(CK_ULONG);;
	}

	return CKR_OK;
}

/*
 * Helper functions to analyse CK fields
 */
size_t sks_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == CKA_CLASS)
		return sizeof(CK_ULONG);
	else
		return 0;
}

size_t sks_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
		return sizeof(CK_ULONG);
	default:
		return 0;
	}
}
int sks_attr_is_array(uint32_t attribute_id)
{
	switch (attribute_id) {
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
	case CKA_ALLOWED_MECHANISMS:
		return 1;
	default:
		return 0;
	}
}
int sks_class_has_boolprop(uint32_t class)
{
	switch (class) {
	case CKO_DATA:
	case CKO_CERTIFICATE:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_DOMAIN_PARAMETERS:
		return 1;
	default:
		return 0;
	}
}
int sks_class_has_type(uint32_t class)
{
	switch (class) {
	case CKO_CERTIFICATE:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_MECHANISM:
	case CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}
int sks_attr_class_is_key(uint32_t class)
{
	switch (class) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		return 1;
	default:
		return 0;
	}
}

/* Convert CK boolean attribute into boolprop1 bit flag. 0 if not applicable */
static const CK_ULONG boolprop_shift2attrib[] = {
	[SKS_PERSISTENT_SHIFT] = CKA_TOKEN,
	[SKS_NEED_AUTHEN_SHIFT] = CKA_PRIVATE,
	[SKS_TRUSTED_FOR_WRAP_SHIFT] = CKA_TRUSTED,
	[SKS_SENSITIVE_SHIFT] = CKA_SENSITIVE,
	[SKS_ENCRYPT_SHIFT] = CKA_ENCRYPT,
	[SKS_DECRYPT_SHIFT] = CKA_DECRYPT,
	[SKS_WRAP_SHIFT] = CKA_WRAP,
	[SKS_UNWRAP_SHIFT] = CKA_UNWRAP,
	[SKS_SIGN_SHIFT] = CKA_SIGN,
	[SKS_SIGN_RECOVER_SHIFT] = CKA_SIGN_RECOVER,
	[SKS_VERIFY_SHIFT] = CKA_VERIFY,
	[SKS_VERIFY_RECOVER_SHIFT] = CKA_VERIFY_RECOVER,
	[SKS_DERIVE_SHIFT] = CKA_DERIVE,
	[SKS_EXTRACT_SHIFT] = CKA_EXTRACTABLE,
	[SKS_LOCALLY_GENERATED_SHIFT] = CKA_LOCAL,
	[SKS_NEVER_EXTRACTABLE_SHIFT] = CKA_NEVER_EXTRACTABLE,
	[SKS_ALWAYS_SENSITIVE_SHIFT] = CKA_ALWAYS_SENSITIVE,
	[SKS_MODIFIABLE_SHIFT] = CKA_MODIFIABLE,
	[SKS_COPIABLE_SHIFT] = CKA_COPYABLE,
	[SKS_DESTROYABLE_SHIFT] = CKA_DESTROYABLE,
	[SKS_ALWAYS_AUTHEN_SHIFT] = CKA_ALWAYS_AUTHENTICATE,
	[SKS_WRAP_FROM_TRUSTED_SHIFT] = CKA_WRAP_WITH_TRUSTED,
};

/* Returns shift position or -1 on error */
int sks_attr2boolprop_shift(CK_ULONG attr)
{
	size_t shift;
	const size_t array_size = sizeof(boolprop_shift2attrib) /
				  sizeof(CK_ULONG);

	/*
	 * Attribute 0 (CKA_CLASS is not a boolean and marks uninitted
	 * cells in array boolprop_shift2attrib[].
	 */
	if (!attr)
		return -1;

	for (shift = 0; shift < array_size; shift++)
		if (attr == boolprop_shift2attrib[shift])
			return (int)shift;

	return -1;
}
