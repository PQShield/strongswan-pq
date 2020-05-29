AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pqsdk-pqtls.la
else
plugin_LTLIBRARIES = libstrongswan-pqsdk-pqtls.la
endif

libstrongswan_pqsdk_pqtls_la_SOURCES = \
	pqsdk_pqtls_plugin.c               \
	kem.c

libstrongswan_pqsdk_pqtls_la_LDFLAGS = \
	-module                            \
	-avoid-version

libstrongswan_pqsdk_pqtls_la_LIBADD  = \
	-lcrypto
