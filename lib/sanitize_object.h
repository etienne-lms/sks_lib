/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SANITIZE_PARAMS_H
#define __SANITIZE_PARAMS_H

#include <pkcs11.h>
#include "serialize_ck.h"

CK_RV serial_sanitize_attributes(void **head, void *ref, size_t ref_size);

/* TODO */
CK_RV serial_sanitize_mechanism(struct serializer *obj);

CK_RV serial_trace_attributes(char *prefix, struct serializer *obj);
CK_RV serial_trace_attributes_from_head(char *prefix, void *ref);


#endif /*__SANITIZE_PARAMS_H*/
