/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <sks_abi.h>

#include "helpers_ck.h"
#include "local_utils.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "serialize_ck.h"

static CK_RV sanitize_class_and_type(struct serializer *dst,
				     struct serializer *src)
{
	char *cur = src->buffer + sizeof_serial_object_head(src);
	char *end = src->buffer + src->size;
	struct sks_ref sks_ref;
	uint32_t class;
	uint32_t type;
	size_t next;

	dst->class = src->class;
	dst->type = src->type;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_attr_is_class(sks_ref.id)) {

			if (sks_ref.size != sks_attr_is_class(sks_ref.id))
				return CKR_TEMPLATE_INCONSISTENT;

			memcpy(&class, cur + sizeof(sks_ref), sks_ref.size);

			if (dst->class != SKS_UNDEFINED_ID &&
			    dst->class != class)
				return CKR_TEMPLATE_INCONSISTENT;

			/* If class not in destination head, serialize it */
			if (dst->config == SKS_ABI_CONFIG_RAWHEAD) {
				CK_RV rv;

				dst->item_count++;
				rv = serialize_buffer(dst, cur, next);
				if (rv)
					return rv;
			}

			dst->class = class;
		}

		/* The attribute is a type-in-class */
		if (sks_attr_is_type(sks_ref.id)) {
			if (sks_ref.size != sks_attr_is_type(sks_ref.id))
				return CKR_TEMPLATE_INCONSISTENT;

			memcpy(&type, sks_ref.data, sks_ref.size);

			if (dst->type != SKS_UNDEFINED_ID &&
			    dst->type != type)
				return CKR_TEMPLATE_INCONSISTENT;

			/* If type not in destination head, serialize it */
			if (dst->config == SKS_ABI_CONFIG_RAWHEAD) {
				CK_RV rv;

				dst->item_count++;
				rv = serialize_buffer(dst, cur, next);
				if (rv)
					return rv;
			}

			dst->type = type;
		}
	}

	/* Sanity */
	if (cur != end) {
		LOG_ERROR("unexpected unalignment\n");
		return CKR_FUNCTION_FAILED;
	}

	/* TODO: verify type against the class */

	return CKR_OK;
}

static CK_RV sanitize_boolprop(struct serializer *dst,
				struct sks_ref *sks_ref,
				char *cur,
				uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;

	/* Get the booloean property shift position and value */
	shift = sks_attr2boolprop_shift(sks_ref->id);
	if (shift < 0)
		return CKR_NO_EVENT;

	if (shift >= SKS_MAX_BOOLPROP_SHIFT)
		return CKR_FUNCTION_FAILED;

	mask = 1 << (shift % 32);
	if ((*(CK_BBOOL *)(cur + sizeof(*sks_ref))) == CK_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = dst->boolprop + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if (*sanity_ptr & mask && value != (*boolprop_ptr & mask))
		return CKR_TEMPLATE_INCONSISTENT;

	*sanity_ptr |= mask;
	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

	/* If no boolprop in destination head, serliase the attribute */
	if (dst->config != SKS_ABI_CONFIG_KEYHEAD) {
		CK_RV rv;

		dst->item_count++;
		rv = serialize_buffer(dst, cur, sizeof(*sks_ref) +
						sks_ref->size);
		if (rv)
			return rv;
	}

	return CKR_OK;
}

static CK_RV sanitize_boolprops(struct serializer *dst,
				struct serializer *src)
{
	char *end= src->buffer + src->size;
	char *cur = src->buffer + sizeof_serial_object_head(src);
	size_t next;
	struct sks_ref sks_ref;
	uint32_t sanity[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	CK_RV rv;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		rv = sanitize_boolprop(dst, &sks_ref, cur, sanity);
		if (rv != CKR_OK && rv != CKR_NO_EVENT)
			return rv;
	}

	return CKR_OK;
}

/* Forward ref since an attribute refernece can contain a list of attribute */
static CK_RV sanitize_attributes_from_head(struct serializer *dst, void *src);

/* Counterpart of serialize_indirect_attribute() */
static CK_RV sanitize_indirect_attr(struct serializer *dst,
				    struct serializer *src,
				    struct sks_ref *sks_ref,
				    char *cur)
{
	struct serializer obj2;
	CK_RV rv;

	/*
	 * Serialized subblobs: current applicable only the key templates which
	 * are tables of attributes.
	 */
	switch (sks_ref->id) {
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
		break;
	default:
		return CKR_NO_EVENT;
	}
	/* Such attributes are expected only for keys (and vendor defined) */
	if (sks_attr_class_is_key(src->class))
		return CKR_TEMPLATE_INCONSISTENT;

	/* Build a new serial object while sanitizing the attributes list */
	rv = sanitize_attributes_from_head(&obj2, cur + sizeof(*sks_ref));
	if (rv)
		return rv;

	rv = serialize_32b(dst, sks_ref->id);
	if (rv)
		return rv;

	rv = serialize_32b(dst, sks_ref->size);
	if (rv)
		return rv;

	rv = serialize_buffer(dst, obj2.buffer, obj2.size);
	if (rv)
		return rv;

	dst->item_count++;

	return rv;
}

/* Warning: one cannot append dat to such initiated serial object */
static CK_RV init_object_from_head(struct serializer *obj, void *ref)

{
	union {
		struct sks_obj_rawhead raw;
		struct sks_obj_genhead gen;
		struct sks_obj_keyhead key;
	} head;

	reset_serial_object(obj);

	memcpy(&head.raw, ref, sizeof(head.raw));

	switch (head.raw.version) {
	case SKS_ABI_VERSION_CK_2_40:
		switch (SKS_ABI_HEAD(head.raw.configuration)) {
		case SKS_ABI_CONFIG_RAWHEAD:
			obj->size = sizeof(head.raw) + head.raw.blobs_size;
			break;
#ifdef SKS_ABI_CONFIG_GENHEAD
		case SKS_ABI_CONFIG_GENHEAD:
			memcpy(&head.gen, ref, sizeof(head.gen));
			obj->size = sizeof(head.gen) + head.gen.blobs_size;
			obj->class = head.gen.class;
			obj->type = head.gen.type;
			break;
#endif
#ifdef SKS_ABI_CONFIG_KEYHEAD
		case SKS_ABI_CONFIG_KEYHEAD:
			memcpy(&head.key, ref, sizeof(head.key));
			obj->size = sizeof(head.key) + head.key.blobs_size;
			obj->class = head.key.class;
			obj->type = head.key.type;
			memcpy(obj->boolprop, &head.key.boolpropl,
				sizeof(uint32_t));
			memcpy(obj->boolprop + 1, &head.key.boolproph,
				sizeof(uint32_t));
			break;
#endif
		default:
			return CKR_FUNCTION_FAILED;
		}
		break;
	default:
		return CKR_FUNCTION_FAILED;
	}

	obj->buffer = ref;
	obj->version = head.raw.version;
	obj->config = head.raw.configuration;

	return CKR_OK;
}

static CK_RV finalize_object(struct serializer *obj)
{
	union {
		struct sks_obj_rawhead raw;
		struct sks_obj_genhead gen;
		struct sks_obj_keyhead key;
	} head;

	switch (obj->version) {
	case SKS_ABI_VERSION_CK_2_40:
		switch (SKS_ABI_HEAD(obj->config)) {
		case SKS_ABI_CONFIG_RAWHEAD:
			head.raw.version = obj->version;
			head.raw.configuration = obj->config;
			head.raw.blobs_size = obj->size - sizeof(head.raw);
			head.raw.blobs_count = obj->item_count;
			memcpy(obj->buffer, &head.raw, sizeof(head.raw));
			break;
#ifdef SKS_ABI_CONFIG_GENHEAD
		case SKS_ABI_CONFIG_GENHEAD:
			head.gen.version = obj->version;
			head.gen.configuration = obj->config;
			head.gen.blobs_size = obj->size - sizeof(head.gen);
			head.gen.blobs_count = obj->item_count;
			head.gen.class = obj->class;
			head.gen.type = obj->type;
			memcpy(obj->buffer, &head.gen, sizeof(head.gen));
			break;
#endif
#ifdef SKS_ABI_CONFIG_KEYHEAD
		case SKS_ABI_CONFIG_KEYHEAD:
			head.key.version = obj->version;
			head.key.configuration = obj->config;
			head.key.blobs_size = obj->size - sizeof(head.key);
			head.key.blobs_count = obj->item_count;
			head.key.class = obj->class;
			head.key.type = obj->type;
			head.key.boolpropl = obj->boolprop[0];
			head.key.boolproph = obj->boolprop[1];
			memcpy(obj->buffer, &head.key, sizeof(head.key));
			break;
#endif
		default:
			return CKR_FUNCTION_FAILED;
		}
		break;
	default:
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

/**
 * serial_raw2gen_attributes - create a genhead serial object from a sks blob.
 *
 * @out_object - output structure tracking the generated serial object
 * @ref - pointer to the rawhead formated serialized object
 *
 * ref points to a blob starting with a sks head.
 * ref may pointer to an unaligned address.
 * This function generates another serial blob starting with a genhead
 * (class and type extracted).
 */
static CK_RV sanitize_attributes_from_head(struct serializer *dst, void *src)
{
	struct serializer ref_obj;
	CK_RV rv;
	char *cur;
	char *end;
	size_t next;

	rv = init_object_from_head(&ref_obj, src);
	if (rv)
		return rv;

	rv = sanitize_class_and_type(dst, &ref_obj);
	if (rv)
		return rv;

	rv = sanitize_boolprops(dst, &ref_obj);
	if (rv)
		return rv;

	cur = ref_obj.buffer + sizeof_serial_object_head(&ref_obj);
	end = ref_obj.buffer + ref_obj.size;
	for (; cur < end; cur += next) {
		struct sks_ref sks_ref;

		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_attr_is_class(sks_ref.id) ||
		    sks_attr_is_type(sks_ref.id) ||
		    sks_attr2boolprop_shift(sks_ref.id) >= 0)
			continue;

		rv = sanitize_indirect_attr(dst, &ref_obj, &sks_ref, cur);
		if (rv == CKR_OK)
			continue;
		if (rv != CKR_NO_EVENT)
			return rv;

		/* It is a standard attribute reference, serializa it */
		dst->item_count++;
		rv = serialize_buffer(dst, cur, next);
		if (rv)
			return rv;
	}

	/* sanity */
	if (cur != end) {
		LOG_ERROR("unexpected none alignement\n");
		return CKR_FUNCTION_FAILED;
	}

	return finalize_object(dst);
}

/* Sanitize ref into head (this duplicates the serial object in memory) */
CK_RV serial_sanitize_attributes(void **head, void *ref, size_t ref_size)
{
	struct serializer dst_obj;
	CK_RV rv;

	if (ref_size < get_serial_size(ref))
		return CKR_FUNCTION_FAILED; // FIXME: invalid arguments

	/* Here call reset_serial_object_rawhead() to get a keyhead object */
	rv = reset_serial_object_rawhead(&dst_obj);
	if (rv)
		return rv;

	rv = sanitize_attributes_from_head(&dst_obj, ref);
	if (rv == CKR_OK)
		*head = dst_obj.buffer;

	release_serial_object(&dst_obj);

	return rv;
}

/*
 * Debug: dump CK attribute array to output trace
 */

static CK_RV trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix */
	prefix2 = malloc(prefix_len + 1 + 4) ;
	memcpy(prefix2, prefix, prefix_len + 1);
	memset(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 1 + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct sks_ref sks_ref;

		memcpy(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		LOG_DEBUG("%s attr 0x%lx (%lu byte) : %02x %02x %02x %02x ...\n",
			prefix, sks_ref.id, sks_ref.size,
			*((char *)cur + sizeof(sks_ref) + 0),
			*((char *)cur + sizeof(sks_ref) + 1),
			*((char *)cur + sizeof(sks_ref) + 2),
			*((char *)cur + sizeof(sks_ref) + 3));

		switch (sks_ref.id) {
		case CKA_WRAP_TEMPLATE:
		case CKA_UNWRAP_TEMPLATE:
		case CKA_DERIVE_TEMPLATE:
			serial_trace_attributes_from_head(prefix2,
							  cur + sizeof(sks_ref));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		LOG_ERROR("unexpected none alignement\n");
	}

	free(prefix2);
	return CKR_OK;
}

CK_RV serial_trace_attributes_from_head(char *prefix, void *ref)
{
	struct sks_obj_rawhead raw;
	char *pre;
	size_t offset;
	CK_RV rv;

	memcpy(&raw, ref, sizeof(raw));
	if (raw.version != SKS_ABI_VERSION_CK_2_40)
		return CKR_TEMPLATE_INCONSISTENT;

	pre = calloc(1, prefix ? strlen(prefix) + 2 : 2) ;
	if (!pre)
		return CKR_HOST_MEMORY;
	if (prefix)
		memcpy(pre, prefix, strlen(prefix));

	LOG_INFO("%s,--- (serial object) Attributes list --------\n", pre);
	LOG_INFO("%s| version 0x%lx  config 0x%lx - %lu item(s) - %lu bytes\n", pre,
		 raw.version, raw.configuration,
		 raw.blobs_count, raw.blobs_size);

	if (raw.version != SKS_ABI_VERSION_CK_2_40) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto bail;
	}

	if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_RAWHEAD) {
		offset = sizeof(raw);
	} else if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_GENHEAD) {
		struct sks_obj_genhead head;

		offset = sizeof(head);
		memcpy(&head, ref, sizeof(head));
		LOG_INFO("%s| class 0x%lx  type 0x%lx\n", pre,
			 head.class, head.type);
	} else if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_KEYHEAD) {
		struct sks_obj_keyhead head;

		offset = sizeof(head);
		memcpy(&head, ref, sizeof(head));
		LOG_INFO("%s| class 0x%lx  type 0x%lx - boolpropl/h 0x%lx/0x%lx\n", pre,
			 head.class, head.type, head.boolpropl, head.boolproph);
	} else {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto bail;
	}

	pre[prefix ? strlen(prefix) + 1 : 0] = '|';
	rv = trace_attributes(pre, (char *)ref + offset,
			      (char *)ref + offset + raw.blobs_size);
	if (rv)
		goto bail;

	LOG_INFO("%s`-----------------------\n", prefix ? prefix : "");

bail:
	free(pre);
	return rv;
}

CK_RV serial_trace_attributes(char *prefix, struct serializer *obj)
{
	return serial_trace_attributes_from_head(prefix, obj->buffer);
}

