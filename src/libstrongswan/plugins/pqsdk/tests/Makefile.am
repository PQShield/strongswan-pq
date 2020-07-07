TESTS = pqsdk_tests

check_PROGRAMS = $(TESTS)

pqsdk_tests_SOURCES = \
    pqsdk_tests.c \
    pqsdk_tests_runner.c

pqsdk_tests_CFLAGS = \
    -I$(top_srcdir)/src/libstrongswan \
    -I$(top_srcdir)/src/libstrongswan/tests \
    -DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
    -DPLUGINS=\""${s_plugins}\"" \
    @COVERAGE_CFLAGS@

pqsdk_tests_LDFLAGS = @COVERAGE_LDFLAGS@
pqsdk_tests_LDADD = \
    $(top_builddir)/src/libstrongswan/libstrongswan.la \
    $(top_builddir)/src/libstrongswan/tests/libtest.la

if USE_PQSDK_PQTLS
    pqsdk_tests_CFLAGS += -DUSE_PQSDK_PQTLS \
    -I$(top_srcdir)/src/libstrongswan/plugins/pqsdk
    pqsdk_tests_LDADD += $(top_builddir)/src/libstrongswan/plugins/pqsdk/pqtls/libstrongswan-pqsdk-pqtls.la
endif


if USE_PQSDK_PQSDKD
    pqsdk_tests_CFLAGS += -DUSE_PQSDK_PQSDKD \
    -I$(top_srcdir)/src/libstrongswan/plugins/pqsdk
    pqsdk_tests_LDADD += $(top_builddir)/src/libstrongswan/plugins/pqsdk/pqsdkd/libstrongswan-pqsdk-pqsdkd.la
endif
