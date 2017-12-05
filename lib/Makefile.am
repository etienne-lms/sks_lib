include_HEADERS		= $(top_srcdir)/lib/include/pkcs11/pkcs11.h
include_HEADERS		+= $(top_srcdir)/lib/include/pkcs11/pkcs11t.h
include_HEADERS		+= $(top_srcdir)/lib/include/pkcs11/pkcs11f.h

lib_LTLIBRARIES		= liboptee_cryptoki.la

AM_CFLAGS		= $(WARNINGCFLAGS)

liboptee_cryptoki_la_LDFLAGS	= -version-info $(LIBVER_CURRENT):$(LIBVER_REVISION):$(LIBVER_AGE)

liboptee_cryptoki_la_SOURCES	= pkcs11_api.c
liboptee_cryptoki_la_SOURCES	+= handle.c handle.h
liboptee_cryptoki_la_SOURCES	+= invoke_ta.c invoke_ta.h
liboptee_cryptoki_la_SOURCES	+= pkcs11_token.c pkcs11_token.h
liboptee_cryptoki_la_SOURCES	+= helpers_ck.c helpers_ck.h
liboptee_cryptoki_la_SOURCES	+= serializer.c serializer.h
liboptee_cryptoki_la_SOURCES	+= serialize_ck.c serialize_ck.h
liboptee_cryptoki_la_SOURCES	+= sanitize_object.c sanitize_object.h

liboptee_cryptoki_la_CFLAGS	= -I$(top_srcdir)/lib/include
liboptee_cryptoki_la_CFLAGS	+= -I$(top_srcdir)/lib/include/pkcs11
liboptee_cryptoki_la_CFLAGS	+= -I$(top_srcdir)/lib/include/libteec

liboptee_cryptoki_la_CFLAGS	+= -D_GNU_SOURCE
liboptee_cryptoki_la_CFLAGS	+= -DCFG_OPTEECK_LOG_LEVEL=$(CFG_OPTEECK_LOG_LEVEL)

liboptee_cryptoki_la_CFLAGS	+= $(AM_CFLAGS)
