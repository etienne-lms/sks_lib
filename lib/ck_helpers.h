/*
 * Copyright (c) 2014-2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __HELPERS_CK_H
#define __HELPERS_CK_H

#include <pkcs11.h>
#include <stdint.h>
#include <stddef.h>
#include <sks_abi.h>
#include <sks_ta.h>

/*
 * Convert structure struct sks_ck_token_info retreived from TA into a
 * cryptoki API compliant CK_TOKEN_INFO structure.
 *
 * struct sks_ck_token_info is defined in the SKS TA API.
 */
CK_RV sks2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct sks_ck_token_info *sks_info);
CK_RV sks2ck_slot_info(CK_SLOT_INFO_PTR ck_info,
			struct sks_ck_slot_info *sks_info);

/*
 * Converts an array on sks ulongs into a array of CK ulongs.
 * Source and destination may not be 32bit aligned.
 */
CK_RV sks2ck_ulong_array(void *dst, void *src, size_t count);

/* Convert a array of mechanism type from sks into CK_MECHANIMS_TYPE */
static inline CK_RV sks2ck_mechanism_type(void *ck, void *sks, size_t count)
{
	return sks2ck_ulong_array(ck, sks, count);
}

/* Convert structure CK_MECHANIMS_INFO from sks to ck (3 ulong fields) */
static inline CK_RV sks2ck_mechanism_info(void *info, void *sks)
{
	return sks2ck_ulong_array(info, sks, 3);
}

/*
 * Define, per object, which common boolean properties can be enable or
 * disable
 */
#define SKS_DATA_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_DATA_BOOLPROPH	0

// TODO
#define SKS_SYMKEY_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_SYMKEY_BOOLPROPH	0

#define SKS_PUBKEY_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_PUBKEY_BOOLPROPH	0

#define SKS_PRIVKEY_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_PRIVKEY_BOOLPROPH	0

#define SKS_CERTIF_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_CERTIF_BOOLPROPH	0

#define SKS_DOMAIN_BOOLPROPL	(SKS_PERSISTENT | SKS_NEED_AUTHEN | \
					SKS_MODIFIABLE | SKS_COPIABLE | \
					SKS_DESTROYABLE)
#define SKS_DOMAIN_BOOLPROPH	0

/*
 * Helper functions to analyse CK fields
 */
size_t sks_attr_is_class(uint32_t attribute_id);
size_t sks_attr_is_type(uint32_t attribute_id);
int sks_attr_is_array(uint32_t attribute_id);
int sks_class_has_boolprop(uint32_t class);
int sks_class_has_type(uint32_t class);
int sks_attr_class_is_key(uint32_t class);

int sks_attr2boolprop_shift(CK_ULONG attr);

#endif /*__HELPERS_CK_H*/
