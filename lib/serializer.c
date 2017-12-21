/*
 * Copyright (c) 2014-2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"

static size_t __sizeof_serial_head(uint32_t version, uint32_t config)
{
	if (version != SKS_ABI_VERSION_CK_2_40)
		return 0;

	switch (SKS_ABI_HEAD(config)) {
	case SKS_ABI_CONFIG_RAWHEAD:
		return sizeof(struct sks_obj_rawhead);
	case SKS_ABI_CONFIG_GENHEAD:
		return sizeof(struct sks_obj_genhead);
	case SKS_ABI_CONFIG_KEYHEAD:
		return sizeof(struct sks_obj_keyhead);
	default:
		return 0;
	}
}

size_t sizeof_serial_head(void *ref)
{
	struct sks_obj_rawhead raw;

	memcpy(&raw, ref, sizeof(raw));

	return __sizeof_serial_head(raw.version, raw.configuration);
}

size_t get_serial_size(void *ref)
{
	struct sks_obj_rawhead raw;

	memcpy(&raw, ref, sizeof(raw));

	return raw.blobs_size +
		__sizeof_serial_head(raw.version, raw.configuration);
}

/*
 * Utilitaries on already serialized object.
 * Serailized object reference is the start address of object head.
 */


uint32_t serial_get_class(void *ref)
{
	uint32_t class;
	uint32_t class_size = sizeof(uint32_t);
	CK_RV rv;

	rv = serial_get_attribute(ref, CKA_CLASS, &class, &class_size);
	if (rv)
		return CK_VENDOR_UNDEFINED_ID;

	return class;
}

uint32_t serial_get_type(void *ref)
{
	struct sks_obj_rawhead *raw = ref;
	char *cur = (char *)ref + sizeof_serial_head(raw);
	char *end = cur + raw->blobs_size;
	size_t next;
	uint32_t type;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (!sks_attr_is_type(sks_ref.id))
			continue;

		if (sks_ref.size != sizeof(uint32_t))
			return SKS_UNDEFINED_ID;

		memcpy(&type, sks_ref.data, sks_ref.size);
		return type;
	}
	/* Sanity */
	if (cur != end)
		LOG_ERROR("unexpected unalignment\n");

	return SKS_UNDEFINED_ID;
}

CK_RV serial_get_attribute_ptr(void *ref, uint32_t attribute,
				void **attr, size_t *attr_size)
{
	struct sks_obj_rawhead *raw = ref;
	char *cur = (char *)ref + sizeof_serial_head(raw);
	char *end = cur + raw->blobs_size;
	size_t next;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		if (attr)
			*attr = &sks_ref.data;
		if (attr_size)
			*attr_size = sks_ref.size;
		return CKR_OK;
	}
	/* Sanity */
	if (cur != end) {
		LOG_ERROR("unexpected unalignment\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_GENERAL_ERROR;		// FIXME: errno
}

CK_RV serial_get_attribute(void *ref, uint32_t attribute,
			   void *attr, size_t *attr_size)
{
	CK_RV rv;
	void *attr_ptr;
	size_t size;

	rv = serial_get_attribute_ptr(ref, attribute, &attr_ptr, &size);
	if (rv)
		return rv;

	if (attr && attr_size && *attr_size < size)
		return CKR_BUFFER_TOO_SMALL;

	if (attr)
		memcpy(attr, attr_ptr, size);
	if (attr_size)
		*attr_size = size;

	return CKR_OK;
}

/*
 * Tools based on serializer structure: used when serializing data
 */

size_t sizeof_serial_object_head(struct serializer *obj)
{
	return __sizeof_serial_head(obj->version, obj->config);
}

size_t get_serial_object_size(struct serializer *obj)
{
	return obj->size;
}

char *get_serial_object_buffer(struct serializer *obj)
{
	return obj->buffer;
}

/*
 * TODO: rename the family into
 *	serial_object_init()
 *	serial_(raw|...)head_init()
 *	serial_object_init_from_head()
 */
void reset_serial_object(struct serializer *obj)
{
	memset(obj, 0, sizeof(*obj));
	obj->class = SKS_UNDEFINED_ID;
	obj->type = SKS_UNDEFINED_ID;
}

CK_RV reset_serial_object_rawhead(struct serializer *obj)
{
	struct sks_obj_rawhead head;

	reset_serial_object(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_RAWHEAD;

	head.version = obj->version;
	head.configuration = obj->config;

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

CK_RV reset_serial_object_genhead(struct serializer *obj)
{
	struct sks_obj_genhead head;

	reset_serial_object(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_GENHEAD;

	head.version = obj->version;
	head.configuration = obj->config;
	head.class = obj->class;
	head.type = obj->type;

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

CK_RV reset_serial_object_keyhead(struct serializer *obj)
{
	struct sks_obj_keyhead head;
	reset_serial_object(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_KEYHEAD;

	head.version = obj->version;
	head.configuration = obj->config;
	head.class = obj->class;
	head.type = obj->type;
	head.boolpropl = *((uint32_t *)obj->boolprop);
	head.boolproph = *((uint32_t *)obj->boolprop + 1);

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

void release_serial_object(struct serializer *obj)
{
	free(obj->buffer);
}

/**
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignement of appended data in the buffer.
 */
CK_RV serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf;
	size_t nlen;
	CK_RV rv;

	nlen = *blen + len;

	buf = realloc(*bstart, nlen);
	if (!buf)
		return CKR_HOST_MEMORY;

	memcpy(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return CKR_OK;
}

CK_RV serialize_32b(struct serializer *obj, uint32_t data)
{
	return serialize(&obj->buffer, &obj->size, &data, sizeof(uint32_t));
}

CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size)
{
	return serialize(&obj->buffer, &obj->size, data, size);
}

CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data)
{
	uint32_t data32 = data;

	return serialize_buffer(obj, &data32, sizeof(data32));
}

CK_RV serialize_size_and_buffer(struct serializer *obj, void *data,
				size_t size)
{
	CK_RV rv;

	rv = serialize_ck_ulong(obj, size);
	if (rv)
		return rv;

	return serialize_buffer(obj, data, size);
}
