include_HEADERS		= $(top_srcdir)/lib/include/pkcs11/pkcs11.h
include_HEADERS		+= $(top_srcdir)/lib/include/pkcs11/pkcs11t.h
include_HEADERS		+= $(top_srcdir)/lib/include/pkcs11/pkcs11f.h

lib_LTLIBRARIES		= liboptee_cryptoki.la

AM_CFLAGS		= $(WARNINGCFLAGS)

liboptee_cryptoki_la_LDFLAGS	= -version-info $(LIBVER_CURRENT):$(LIBVER_REVISION):$(LIBVER_AGE)

liboptee_cryptoki_la_SOURCES	= pkcs11_api.c
liboptee_cryptoki_la_SOURCES	+= handle.c handle.h

liboptee_cryptoki_la_CFLAGS	= -I$(top_srcdir)/lib/include
liboptee_cryptoki_la_CFLAGS	+= -I$(top_srcdir)/lib/include/pkcs11
liboptee_cryptoki_la_CFLAGS	+= -I$(top_srcdir)/lib/include/libteec

liboptee_cryptoki_la_CFLAGS	+= -D_GNU_SOURCE
liboptee_cryptoki_la_CFLAGS	+= -DCFG_OPTEECK_LOG_LEVEL=$(CFG_OPTEECK_LOG_LEVEL)

liboptee_cryptoki_la_CFLAGS	+= $(AM_CFLAGS)
