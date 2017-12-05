/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <sks_abi.h>
#include <stdlib.h>
#include <string.h>

#include "helpers_ck.h"
#include "local_utils.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "serialize_ck.h"

/*
 * Generic way of serializing CK keys, certif, mechanism parameters, ...
 * In cryptoki 2.40 parameters are almost all packaged as struture below:
 */
struct ck_ref {
	CK_ULONG id;
	CK_BYTE_PTR ptr;
	CK_ULONG len;
};

/*
 * Append cryptokey generic buffer reference structure into a sks serial
 * object.
 *
 * ck_ref points to a structure aligned CK reference (attributes or else)
 */
static CK_RV serialize_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, ref->len);
	if (rv)
		return rv;

	return serialize_buffer(obj, ref->ptr, ref->len);
}

/*
 * ck_ref points to a structure aligned CK reference (attributes or else)
 *
 * Same as serialize_ck_ref but reference is a ULONG so the blob size
 * to be set accoring to the 32bit/64bit configuration of target CK ABI.
 */
static CK_RV serialize_ulong_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_ULONG ck_value;
	uint32_t sks_value;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, sizeof(sks_value));
	if (rv)
		return rv;

	memcpy(&ck_value, ref->ptr, sizeof(CK_ULONG));
	sks_value = ck_value;

	return serialize_buffer(obj, &sks_value, sizeof(sks_value));
}

/*
 * This is for attributes that contains data memory indirections.
 * They are identified from the attribute type CKA_...
 *
 * @obj - ref used to track the serial object being created
 * @attribute - pointer to a structure aligned of the CK_ATTRIBUTE struct
 */
static CK_RV serialize_indirect_attribute(struct serializer *obj,
					  CK_ATTRIBUTE_PTR attribute)
{
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG count;
	CK_RV rv;
	struct serializer obj2;
	struct sks_obj_rawhead *head;

	switch (attribute->type) {
	/* These are serialized each seperately */
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
		count = attribute->ulValueLen / sizeof(CK_ATTRIBUTE);
		attr = (CK_ATTRIBUTE_PTR)attribute->pValue;
		break;
	default:
		return CKR_NO_EVENT;
	}

	/*
	 * Serialized data: expected [attr-id][length][blobs]
	 * where [blobs] is a sks rawhead object ([sks-rawhead][blobs])
	 * So let's start by building the rawhead object.
	 */

	rv = reset_serial_object_rawhead(&obj2);
	if (rv)
		return rv;

	rv = serialize_ck_attributes(&obj2, attr, count);
	if (rv)
		return rv;

	/* serialized: [attr-id|fullsize|blobs] */
	rv = serialize_ck_ulong(obj, attribute->type);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, obj2.size);
	if (rv)
		return rv;

	return serialize_buffer(obj, obj2.buffer, obj2.size);
}

void trace_buffer(void*p, size_t l);

/* CK attribute reference arguments are list of attribute item */
CK_RV serialize_ck_attributes(struct serializer *obj,
				CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	/* Serialize attribute in the rawhead serial object */
	struct sks_obj_rawhead head;
	CK_ATTRIBUTE_PTR cur_attr = attributes;
	CK_ULONG n = count;
	CK_RV rv = CKR_OK;

	rv = reset_serial_object_rawhead(obj);
	if (rv)
		return rv;

	obj->item_count = count;

	for (; n; n--, cur_attr++) {
		CK_ATTRIBUTE attr;

		memcpy(&attr, cur_attr, sizeof(attr));

		if (sks_attr_is_class(attr.type) ||
		    sks_attr_is_type(attr.type)) {
			rv = serialize_ulong_ck_ref(obj, &attr);
			if (rv)
				return rv;

			continue;
		}

		rv = serialize_indirect_attribute(obj, &attr);
		if (rv == CKR_OK)
			continue;

		if (rv != CKR_NO_EVENT)
			return rv;

		rv = serialize_ck_ref(obj, &attr);
		if (rv)
			return rv;
	}

	/* Fill the serial object head */
	head.version = obj->version;
	head.configuration = obj->config;
	head.blobs_size = obj->size - sizeof(head);
	head.blobs_count = obj->item_count;
	memcpy(obj->buffer, &head, sizeof(head));

	LOG_DEBUG(" serialize: ver %x cfg %x / sz %x #%u / [ %x %x ] / [ %x %x ] \n",
		head.version, head.configuration,
		head.blobs_size, head.blobs_count,
		((struct sks_obj_keyhead *)&head)->class,
		((struct sks_obj_keyhead *)&head)->type,
		((struct sks_obj_keyhead *)&head)->boolpropl,
		((struct sks_obj_keyhead *)&head)->boolproph);

	return CKR_OK;
}

/*
 * Serialization of CK mechanism parameters
 *
 * Most mechanism have no parameters.
 * Some mechanism have a single 32bit parameter.
 * Some mechanism have a specific parameter structure which may contain
 * indirected data (data referred by a buffer pointer).
 *
 * Below are each strcuture specific mechanisms parameters.
 *
 * Becareful that CK_ULONG based types translate to 32bit sks ulong fields.
 */

/*
 * typedef struct CK_AES_CTR_PARAMS {
 *	CK_ULONG ulCounterBits;
 *	CK_BYTE cb[16];
 * } CK_AES_CTR_PARAMS;
 */
static CK_RV serialize_mecha_aes_ctr(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_AES_CTR_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, param->ulCounterBits);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->cb, sizeof(param->cb));
	if (rv)
		return rv;

	return rv;
}

/*
 * typedef struct CK_GCM_PARAMS {
 *	CK_BYTE_PTR       pIv;
 *	CK_ULONG          ulIvLen;
 *	CK_ULONG          ulIvBits;
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulTagBits;
 * } CK_GCM_PARAMS;
 */
static CK_RV serialize_mecha_gcm(struct serializer *obj,
				 CK_MECHANISM_PTR mecha)
{
	CK_GCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_buffer(obj, param->pIv, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulIvBits);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulTagBits);
	if (rv)
		return rv;

	return rv;
}

/*
 * typedef struct CK_CCM_PARAMS {
 *	CK_ULONG          ulDataLen;
 *	CK_BYTE_PTR       pNonce;
 *	CK_ULONG          ulNonceLen;
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulMACLen;
 *} CK_CCM_PARAMS;
 */
static CK_RV serialize_mecha_ccm(struct serializer *obj,
				 CK_MECHANISM_PTR mecha)
{
	CK_CCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, param->ulDataLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pNonce, param->ulNonceLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulMACLen);
	if (rv)
		return rv;

	return rv;
}

/**
 * serialize_ck_mecha_params - serialize a mechanism type & params
 *
 * @obj - serializer used to track the serialization
 * @mechanism - pointer of the in structure aligned CK_MECHANISM.
 *
 * Serialized content:
 *	[sks-mechanism-type][sks-mechanism-param-blob]
 *
 * [sks-mechanism-param-blob] depends on mechanism type ID, see
 * serialize_mecha_XXX().
 */
CK_RV serialize_ck_mecha_params(struct serializer *obj,
				CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM mecha;
	CK_RV rv;

	reset_serial_object(obj);

	memcpy(&mecha, mechanism, sizeof(mecha));
	obj->class = CKO_MECHANISM;
	obj->type = mecha.mechanism;
	rv = serialize_ck_ulong(obj, mecha.mechanism);
	if (rv)
		return rv;

	switch (mecha.mechanism) {
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
		/* No parameter for these mechanisms */
		return CKR_OK;
	case CKM_AES_CTR:
		return serialize_mecha_aes_ctr(obj, &mecha);
	case CKM_AES_CCM:
		return serialize_mecha_ccm(obj, &mecha);
	case CKM_AES_GCM:
		return serialize_mecha_gcm(obj, &mecha);
	default:
		return CKR_TEMPLATE_INCONSISTENT;
	}
}
