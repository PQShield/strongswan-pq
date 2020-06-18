AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) -I/opt/pqsdk/includes

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pqsdk-pqsdkd.la
else
plugin_LTLIBRARIES = libstrongswan-pqsdk-pqsdkd.la
endif

libstrongswan_pqsdk_pqsdkd_la_SOURCES = \
	pqsdkd_plugin.c               	\
	kem.c

libstrongswan_pqsdk_pqsdkd_la_LDFLAGS = \
	-L/opt/pqsdk/lib 		\
	-module                         \
	-avoid-version

libstrongswan_pqsdk_pqsdkd_la_LIBADD  = \
	-lcrypto -lpq_message_lib
