AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) -I$(PQSDK_INC_DIR)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pqsdk-pqsdkd.la
else
plugin_LTLIBRARIES = libstrongswan-pqsdk-pqsdkd.la
endif

libstrongswan_pqsdk_pqsdkd_la_SOURCES = \
	comm.c                              \
	kem.c								\
	pqsdkd_plugin.c

libstrongswan_pqsdk_pqsdkd_la_LDFLAGS = \
	-L$(PQSDK_LIB_DIR) 					\
	-module								\
	-avoid-version

libstrongswan_pqsdk_pqsdkd_la_LIBADD  = \
	-l$(PQ_MESSAGE_LIB)
