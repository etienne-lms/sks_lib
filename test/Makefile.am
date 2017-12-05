bin_PROGRAMS = sks-test

AM_CFLAGS		= $(WARNINGCFLAGS)

sks_test_SOURCES	= sks-test.c
sks_test_SOURCES	+= test-objects.c

sks_test_CFLAGS 	= $(AM_CFLAGS)
sks_test_CFLAGS 	+= -I$(top_srcdir)/lib/include/pkcs11/

sks_test_LDFLAGS	= $(TEEC_LIBS)

sks_test_LDADD		= ../lib/liboptee_cryptoki.la

