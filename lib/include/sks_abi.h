/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_ABI_H__
#define __SKS_ABI_H__

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/**
 * # Serialization of structured data
 *
 * Agrument references used in the Cryptoki API are:
 * - list of attributes. Attributes may contain non serialized data (buffer
 *   referenced in the attributes structures. A attributes can also include
 *   itself a list of attributes: i.e wrap templates on symmetric and public
 *   keys.
 * - list of mechanism parameters description. Each may contain indirections
 *   of data content, through buffer pointers.
 * - Buffers of data to be process by the secure side.
 * - Buffers of data proceeded by the secure side.
 *
 * SKS serializes all content of these argument references in a contiguous
 * (at least virtually) memory buffer. This serialization is required to
 * transmit in a signle memory reference at versitile set of strusted data
 * as key attributes list, mechanism/transformation parameters.
 *
 * SKS/CK library blindly serializes client data into so-called objects.
 * The SKS TA runs a identification an sanity pass on the object content.
 * The same sanity filtering can be run in the library.
 *
 * Client and TA can use the serialized object to transfer data.
 * TA can use the serialized objects to store the data in a backend storage.
 *
 * # Serializing fixed size and variable size data
 *
 * Data of known type are stored straight while any variable length data,
 * referenced by some pointer, is serialized storing first the data size
 * in byte then the full data as a binary blob. This code takes care of
 * buffer references that themsleves contain other indirect references.
 *
 * A serialized object start with a structure header that introduces the
 * binary blob presented. The header provides the byte size of the serialized
 * blob and the number of formated items to parse in the blob.
 *
 * # ABI of serialized data and versioning
 *
 * To prevent compatibility issues in client/TA ABI and in object
 * storage ABI, the serialized object starts with a header providing
 * information on the ABI used.
 *
 * The ABI version refers to the reference for function prototypes, IDs and
 * data structure.
 *
 * A second field describes the ABI in the header: the configuration info.
 * In the cryptoki, the CK_ULONG can be a 32bit or a 64bit. The LSBit of
 * (note: client and TA share little-endian format on our Arm cores).
 *	configuration & 0x1 == 0x0 => ULONG represents a 32bit.
 *	configuration & 0x1 == 0x1 => ULONG represents a 64bit.
 *
 * # Header structure and version 0.0.0 and 0.1.0
 *
 * Serialization ABI v0.x is based on PCKS#11 v2.40-errata01. Data are present
 * as serialized blob with a header structure:
 *
 *	struct sks_obj_minhead {
 *		uint32_t version;
 *		uint32_t configuration;
 *		uint32_t blobs_size;
 *		uint32_t blobs_count;
 *		uint8_t blobs[];
 *	};
 *
 * Serialization ABI v1.0 is based on PCKS#11 v2.40-errata01 IDs and
 * structures with a ULONG size set as 32bit but replaces some serialized data
 * blobs with identifed field in the header. For example the serialized object
 * that represents a keys starts with the following struct:
 *
 *	struct sks_obj_head {
 *		uint32_t version;
 *		uint32_t configuration;
 *		uint32_t class;
 *		uint32_t type;
 *		uint32_t boolpropl;
 *		uint32_t boolproph;
 *		uint32_t blobs_size;
 *		uint32_t blobs_count;
 *		uint8_t blobs[];
 *	};
 */

/* SKS ABI relies on PCKS#11 definitions and prototypes */
#include <pkcs11.h>

/* # 32bit versus 64bit
 *
 * Issue with CK_ULONG being either a 32bit or a 64bit.
 * Serialized object header uses the cryptoki API/ABI but with
 * the CK_ULONG and CK_LONG types being forced the 32bit data types.
 *
 * The fields that must be taken care in serialized data are:
 * - object class (attribute class).
 * - object type.
 * - attribute indirection: type and byte size are ulong.
 * - mechanism indirection: type and byte size are ulong.
 * - mechanism parameter specific structure.
 * - any vendor specific structure that relies in long int type.
 * All these are stored in 32bit in serialized objects.
 */

/*
 * ABI version 0.0.0: PKCS11_2_40e-01 structures/IDs in serialized blobs.
 * Object starts with a header of type struct sks_obj_rawhead.
 */
#define SKS_ABI_VERSION_CK_2_40		0x00000000

#define SKS_ABI_CONFIG_HEADMASK		0xFF
#define SKS_ABI_CONFIG_RAWHEAD		0x01
#define SKS_ABI_CONFIG_GENHEAD		0x02
#define SKS_ABI_CONFIG_KEYHEAD		0x03

#define SKS_ABI_HEAD(cfg)		((cfg) & SKS_ABI_CONFIG_HEADMASK)

/* Item reference in a serial blob */
struct sks_ref {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * Header of a serialised memory object in raw format.
 * Format use in ABI 0.0.x.
 *
 * @version - mobj ABI version, see SKS_OBJABI_VERSION_xxx
 * @configuration - configuration info, i.e 32b/64b ULONG ABI
 * @blobs_size; byte size of the serialized data
 * @blobs_count; number of items in the blob
 * @blobs - then starts the blob binary data
 */
struct sks_obj_rawhead {
	uint32_t version;
	uint32_t configuration;
	uint32_t blobs_size;
	uint32_t blobs_count;
	uint8_t blobs[];
};

/*
 * WARNING about structures sks_obj_genhead and sks_obj_gkeyhead below.
 *
 * These aim at storing some specific attributes into the serial object head
 * to prevent scanning the whle object for PKCS11 common object attributes as
 * class, type and some boolean properties.
 * However, not shure this is really useful...
 */

/*
 * Header of an analysed generic serialized object with main object info
 * available from the head structure. The blob may content the redondant
 * info in the blob (unless the object has been nicely sanitize to optimize
 * a little the memory footprint.
 * Format use in ABI 0.1.x. for generic objects.
 *
 * ... see struct sks_mobj_rawhead
 * @class - object class id (from CK litterature): key, certif, etc...
 * @type - object type id, per class, i.e aes or des3 in the key class.
 */
struct sks_obj_genhead {
	uint32_t version;
	uint32_t configuration;
	uint32_t blobs_size;
	uint32_t blobs_count;
	uint32_t class;
	uint32_t type;
	uint8_t blobs[];
};

static inline size_t sks_genobj_size(struct sks_obj_genhead *obj)
{
	return sizeof(struct sks_obj_genhead) + obj->blobs_size;
}

/*
 * Header of an analysed serialized object with class, type and several
 * common boolean attributes/properties stored as bit flags in the header.
 *
 * Format use in ABI 0.1.x for cryptoki keys (sym/pub/priv), data and
 * certificates.
 *
 * ... see struct sks_mobj_rawhead
 * @class - object class id (from CK litterature): key, certif, etc...
 * @type - object type id, per class, i.e aes or des3 in the key class.
 * @boolpropl - 32bit bitmask storing boolean properties #0 to #31.
 * @boolproph - 32bit bitmask storing boolean properties #32 to #64.
 */
struct sks_obj_keyhead {
	uint32_t version;
	uint32_t configuration;
	uint32_t blobs_size;
	uint32_t blobs_count;
	uint32_t class;
	uint32_t type;
	uint32_t boolpropl;
	uint32_t boolproph;
	uint8_t blobs[];
};

/*
 * SKS vendor defined attributes
 *
 * CK uses value 0x80000000 as the base value for vendor defined IDs.
 * We use this to define a SKS ID for undefined values. The ID must fit in
 * 32bit so we use 32bit 0xFFFFFFFF.
 *
 * CK_VENDOR_UNDEFINED_ID	This ID reflects an undefined attribute class.
 *				This ID is used when sanitizing client inputs.
 *				SKS_UNDEFINED_ID is the SKS 32bit ID equivalent
 *				in SKS ABI
 *
 * CKA_SKS_SECSTOR_DATA		Reference for the object data in the secure
 *				storage of the TEE (TEE persistent object).
 *				This ID is generated by the TA and never
 *				clearly exposed to clients (sensitive!)
 */
#define CK_VENDOR_UNDEFINED_ID		0xFFFFFFFFUL
#define SKS_UNDEFINED_ID		((uint32_t)CK_VENDOR_UNDEFINED_ID)

#define CKA_SKS_SECSTOR_DATA		((uint32_t)0x80000001)

/*
 * The bit flags use to define common boolean properties of the
 * objects. These flags are all inited. Almost all match a boolean attribute
 * from the PKCS#11 2.40. They are stored in the header structure of serialized
 * object used by SKS.
 */
#define SKS_PERSISTENT_SHIFT		0	/* bitflag for CKA_TOKEN */
#define SKS_NEED_AUTHEN_SHIFT		1	/* bitflag for CKA_PRIVATE */
#define SKS_TRUSTED_FOR_WRAP_SHIFT	3	/* bitflag for CKA_TRUSTED */
#define SKS_SENSITIVE_SHIFT		4	/* bitflag for CKA_SENSITIVE */
#define SKS_ENCRYPT_SHIFT		5	/* bitflag for CKA_ENCRYPT */
#define SKS_DECRYPT_SHIFT		6	/* bitflag for CKA_DECRYPT */
#define SKS_WRAP_SHIFT			7	/* bitflag for CKA_WRAP */
#define SKS_UNWRAP_SHIFT		8	/* bitflag for CKA_UNWRAP */
#define SKS_SIGN_SHIFT			9	/* bitflag for CKA_SIGN */
#define SKS_SIGN_RECOVER_SHIFT		10	/* bitflag for CKA_SIGN_RECOVER */
#define SKS_VERIFY_SHIFT		11	/* bitflag for CKA_VERIFY */
#define SKS_VERIFY_RECOVER_SHIFT	12	/* bitflag for CKA_VERIFY_RECOVER */
#define SKS_DERIVE_SHIFT		13	/* bitflag for CKA_DERIVE */
#define SKS_EXTRACT_SHIFT		14	/* bitflag for CKA_EXTRACTABLE */
#define SKS_LOCALLY_GENERATED_SHIFT	15	/* bitflag for CKA_LOCAL */
#define SKS_NEVER_EXTRACTABLE_SHIFT	16	/* bitflag for CKA_NEVER_EXTRACTABLE */
#define SKS_ALWAYS_SENSITIVE_SHIFT	17	/* bitflag for CKA_ALWAYS_SENSITIVE */
#define SKS_MODIFIABLE_SHIFT		18	/* bitflag for CKA_MODIFIABLE */
#define SKS_COPIABLE_SHIFT		19	/* bitflag for CKA_COPYABLE */
#define SKS_DESTROYABLE_SHIFT		20	/* bitflag for CKA_DESTROYABLE */
#define SKS_ALWAYS_AUTHEN_SHIFT		21	/* bitflag for CKA_ALWAYS_AUTHENTICATE */
#define SKS_WRAP_FROM_TRUSTED_SHIFT	22	/* bitflag for CKA_WRAP_WITH_TRUSTED */

#define SKS_PERSISTENT		(1 << SKS_PERSISTENT_SHIFT)
#define SKS_NEED_AUTHEN		(1 << SKS_NEED_AUTHEN_SHIFT)
#define SKS_TRUSTED_FOR_WRAP	(1 << SKS_TRUSTED_FOR_WRAP_SHIFT)
#define SKS_SENSITIVE		(1 << SKS_SENSITIVE_SHIFT)
#define SKS_ENCRYPT		(1 << SKS_ENCRYPT_SHIFT)
#define SKS_DECRYPT		(1 << SKS_DECRYPT_SHIFT)
#define SKS_WRAP		(1 << SKS_WRAP_SHIFT)
#define SKS_UNWRAP		(1 << SKS_UNWRAP_SHIFT)
#define SKS_SIGN		(1 << SKS_SIGN_SHIFT)
#define SKS_SIGN_RECOVER	(1 << SKS_SIGN_RECOVER_SHIFT)
#define SKS_VERIFY		(1 << SKS_VERIFY_SHIFT)
#define SKS_VERIFY_RECOVER	(1 << SKS_VERIFY_RECOVER_SHIFT)
#define SKS_DERIVE		(1 << SKS_DERIVE_SHIFT)
#define SKS_EXTRACT		(1 << SKS_EXTRACT_SHIFT)
#define SKS_LOCALLY_GENERATED	(1 << SKS_LOCALLY_GENERATED_SHIFT)
#define SKS_NEVER_EXTRACTABLE	(1 << SKS_NEVER_EXTRACTABLE_SHIFT)
#define SKS_ALWAYS_SENSITIVE	(1 << SKS_ALWAYS_SENSITIVE_SHIFT)
#define SKS_MODIFIABLE		(1 << SKS_MODIFIABLE_SHIFT)
#define SKS_COPIABLE		(1 << SKS_COPIABLE_SHIFT)
#define SKS_DESTROYABLE		(1 << SKS_DESTROYABLE_SHIFT)
#define SKS_ALWAYS_AUTHEN	(1 << SKS_ALWAYS_AUTHEN_SHIFT)
#define SKS_WRAP_FROM_TRUSTED	(1 << SKS_WRAP_FROM_TRUSTED_SHIFT)

#endif /*__SKS_ABI_H*/
