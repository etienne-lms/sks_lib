/*
 * Copyright (c) 2014-2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_CK_DEBUG_H
#define __SKS_CK_DEBUG_H

#include <pkcs11.h>

/* Return a pointer to a string buffer of "CKA_xxx\0" attribute ID */
const char *cka2str(CK_ATTRIBUTE_TYPE id);

/* Return a pointer to a string buffer of "CKR_xxx\0" attribute ID */
const char *ckr2str(CK_RV id);

#endif /*__SKS_CK_DEBUG_H*/
