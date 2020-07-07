/*
 * Copyright (C) 2020 Kris Kwiatkowski
 * PQShield LTD, UK
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <test_runner.h>
#include <library.h>

/* declare test suite constructors */
#define TEST_SUITE(x) test_suite_t* x();
#include "pqsdk_tests.h"
#undef TEST_SUITE

static test_configuration_t tests[] = {
#define TEST_SUITE(x) \
	{ .suite = x, },
#include "pqsdk_tests.h"
	{ .suite = NULL, }
};

static bool test_runner_init(bool init) {
	struct sigaction action;

	if (!init) {
		lib->processor->set_threads(lib->processor, 0);
		lib->processor->cancel(lib->processor);
		lib->plugins->unload(lib->plugins);
		return TRUE;
	}

	lib->settings->set_str(lib->settings, "%s.plugins.pqsdk-pqsdkd.socket_path",
		"unix:///tmp/pqsdkd.ut.sock", lib->ns);
	/**
	 * Min 2 connections as we have tests which create initiator & responders at
	 * the same time.
	 */
	lib->settings->set_int(lib->settings, "%s.plugins.pqsdk-pqsdkd.pqsdkd_conn_n",
		2, lib->ns);

	lib->settings->set_int(lib->settings, "%s.plugins.pqsdk-pqsdkd.reconnect_timeout",
		10000, lib->ns);

	char *plugins, *plugindir;

	plugins = lib->settings->get_str(lib->settings,
		"tests.load", PLUGINS);
	plugindir = lib->settings->get_str(lib->settings,
		"tests.plugindir", PLUGINDIR);
	dbg_default_set_level(1);

	/**
	 * Ignore sigpipe. Needed in case, pqsdkd has crashed
	 * but client is still trying to write. No changes in
	 * Charon are needed as this is already implemented
	 * there.
	 */
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
	pthread_sigmask(SIG_SETMASK, &action.sa_mask, NULL);

	plugin_loader_add_plugindirs(plugindir, plugins);
	if (!lib->plugins->load(lib->plugins, plugins)) {
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char *argv[]) {
	return test_runner_run("pqsdk_pqtls", tests, test_runner_init);
}
