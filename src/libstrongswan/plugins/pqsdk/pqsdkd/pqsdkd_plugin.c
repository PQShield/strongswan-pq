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

#include <assert.h>
#include <stdbool.h>

#include <library.h>
#include <plugins/plugin_feature.h>
#include <threading/mutex.h>
#include <utils/debug.h>

#include "comm.h"
#include "kem.h"
#include "pqsdkd_plugin.h"
#include "processing/jobs/callback_job.h"

extern linked_list_t *connection_list;
extern mutex_t *connection_list_mutex;

typedef struct private_pqsdkd_plugin_t private_pqsdkd_plugin_t;

struct private_pqsdkd_plugin_t {

	/**
	 * Public interface for the plugin. Always
	 * must go first.
	 */
	pqsdkd_plugin_t public;

	/**
	 * Indicates weather PQSDK is initialized.
	 */
	bool is_pqsdk_on;

	/**
	 * Number of connections to PQSDKd
	 */
	int pqsdkd_conn_n;

	/**
	 * Max amount of time read and write operation is allowed
	 * to take before ex_cond times out. Default 3sec.
	 */
	int message_exchange_timeout;
};

job_requeue_t try_connect(comm_t* comm) {
	job_requeue_t ret = JOB_REQUEUE_NONE;

	if (!comm || !comm->id) {
		// Implementation error
		return JOB_REQUEUE_NONE;
	}

	if (!comm_lock_by_id(connection_list, comm->id)) {
		return JOB_RESCHEDULE_MS(comm->reconnect_timeout);
	}

	if (comm->reconnect) {
		comm->stream->destroy(comm->stream);
		comm->reconnect = false;
	} else if (comm->stream) {
		// Stream is already created, just quit.
		goto end;
	}

	comm->stream = lib->streams->connect(
		lib->streams, comm->socket_path);
	if (!comm->stream) {
		ret = JOB_RESCHEDULE_MS(comm->reconnect_timeout);
		goto end;
	}

end:
	comm_unlock(connection_list, comm->id);
	return ret;
}

static int init_pqsdkd(private_pqsdkd_plugin_t *plugin) {
	if (plugin->is_pqsdk_on) {
		// already initialized
		goto end;
	}
	char *socket_path;
	int reconnect_timeout;

	plugin->pqsdkd_conn_n = lib->settings->get_int(lib->settings,
		"%s.plugins.pqsdk-pqsdkd.pqsdkd_conn_n", 1, lib->ns);
	plugin->message_exchange_timeout = lib->settings->get_int(lib->settings,
		"%s.plugins.pqsdk-pqsdkd.message_exchange_timeout", 3000, lib->ns);
	reconnect_timeout = lib->settings->get_int(lib->settings,
		"%s.plugins.pqsdk-pqsdkd.reconnect_timeout", 100, lib->ns);
	socket_path = lib->settings->get_str(lib->settings,
		"%s.plugins.pqsdk-pqsdkd.socket_path", NULL, lib->ns);
	if (!socket_path) {
		DBG1(DBG_LIB, "Initialization failed PQSDKd socket not found. "
			"Unable to connect to the PQSDKd daemon.");
		goto end;
	}

	for (size_t i = 0; i<plugin->pqsdkd_conn_n; i++) {
		comm_t *comm = (comm_t*)malloc(sizeof(*comm));
		if (!comm) {
			DBG1(DBG_LIB, "Memory allocation failed.");
			goto end;
		}
		memset(comm, 0, sizeof(*comm));

		comm->id = i+1;
		comm->socket_path = socket_path;
		comm->reconnect_timeout = reconnect_timeout;
		if (!comm_add(connection_list, comm)) {
			DBG1(DBG_LIB, "PQSDKd requestor can't be initialized.");
			return FALSE;
		}

	    comm->stream = lib->streams->connect(
	            lib->streams, comm->socket_path);
	    if (!comm->stream) {
	    	// PQSDKd not available now. Try later
			lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio((callback_job_cb_t)try_connect, comm,
					NULL, (callback_job_cancel_t)return_false, JOB_PRIO_HIGH));
		}
	}

	plugin->is_pqsdk_on = true;

end:
	if (plugin->is_pqsdk_on) {
		lib->set(lib, "pqsdkd-connectors-list", connection_list);
		lib->set(lib, "message-exchange-timeout", &plugin->message_exchange_timeout);
	}

	return (int)plugin->is_pqsdk_on;
}

METHOD(plugin_t, get_name, char*,
	private_pqsdkd_plugin_t *this)
{
	return "pqsdk-pqsdkd";
}

METHOD(plugin_t, get_features, int,
	private_pqsdkd_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, pqsdkd_kem_create),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L1),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L3),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L5),
			PLUGIN_PROVIDE(KE, KE_KYBER_L1),
			PLUGIN_PROVIDE(KE, KE_KYBER_L3),
			PLUGIN_PROVIDE(KE, KE_KYBER_L5),
			PLUGIN_PROVIDE(KE, KE_NTRU_HPS_L1),
			PLUGIN_PROVIDE(KE, KE_NTRU_HRSS_L3),
			PLUGIN_PROVIDE(KE, KE_SABER_L1),
			PLUGIN_PROVIDE(KE, KE_SABER_L3),
			PLUGIN_PROVIDE(KE, KE_SABER_L5),
			PLUGIN_PROVIDE(KE, KE_RND5_5D_CCA_L1),
			PLUGIN_PROVIDE(KE, KE_RND5_5D_CCA_L3),
			PLUGIN_PROVIDE(KE, KE_RND5_5D_CCA_L5),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_pqsdkd_plugin_t *this)
{
	if (connection_list) {
		comm_clean_list(connection_list);
		connection_list->destroy(connection_list);
	}

	if (connection_list_mutex) {
		connection_list_mutex->destroy(connection_list_mutex);
	}

	free(this);
}

plugin_t *pqsdk_pqsdkd_plugin_create()
{
	private_pqsdkd_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	// Create connection_list and connection_list_mutex.
	connection_list_mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	connection_list = linked_list_create();

	if (!connection_list_mutex || !connection_list) {
		DBG1(DBG_LIB, "PQSDK:PQSDKd connection list initialization failed");
		return NULL;
	}

	if (!init_pqsdkd(this)) {
		DBG1(DBG_LIB, "PQSDK:PQSDKd initialization failed");
		return NULL;
	}

	// Must have at least 2 threads for event based communication.
	if (lib->processor->get_total_threads(lib->processor) < 2)
	{
		dbg_default_set_level(0);
		lib->processor->set_threads(lib->processor, 2);
		dbg_default_set_level(1);
	}

	return &this->public.plugin;
}
