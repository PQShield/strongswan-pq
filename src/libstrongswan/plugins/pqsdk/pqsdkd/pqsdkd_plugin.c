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

#include <stdbool.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <library.h>
#include <plugins/plugin_feature.h>
#include <threading/thread_value.h>
#include <utils/debug.h>

#include "pqsdkd_plugin.h"
#include "kem.h"

// max number of clients pqsdkd connection can accept
#define MAX_CLIENTS 1

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
     * PQSDKd communication context
     */
    comm_t comm;
};

static int init_pqsdkd(private_pqsdkd_plugin_t *plugin) {
    struct sockaddr_un sun = {0};
    int ret;

    if (plugin->is_pqsdk_on) {
        // already initialized
        goto end;
    }

    plugin->comm.socket_path = lib->settings->get_str(lib->settings,
        "%s.plugins.pqsdk-pqsdkd.socket_path", NULL, lib->ns);

	if (!plugin->comm.socket_path) {
		DBG1(DBG_LIB, "Initialization failed PQSDKd socket not found. "
			"Unable to connect to the PQSDKd daemon.");
		goto end;
	}
	unlink(plugin->comm.socket_path);

    ret = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ret == -1) {
        DBG1(DBG_LIB, "Can't open a socket FD=%d:\n%s", ret, strerror(errno));
        goto end;
    }
    plugin->comm.fd = ret;

    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, plugin->comm.socket_path, sizeof(sun.sun_path) - 1);
    ret = bind(plugin->comm.fd, (struct sockaddr *)&sun, sizeof(sun));
    if (ret == -1) {
        DBG1(DBG_LIB, "Can't bind to FD=%d:\n%s", plugin->comm.fd, strerror(errno));
        goto end;
    }

    if (listen(plugin->comm.fd, MAX_CLIENTS) == -1) {
        DBG1(DBG_LIB, "Can't set FD=%d to listen:\n%s", plugin->comm.fd, strerror(errno));
        goto end;
    }

    /**
	 *  TODO: This may break strongswan initialization. Must be change once
	 *        we switch daemon to work as a server.
	 */
    ret = accept(plugin->comm.fd, NULL, NULL);
    if (ret == -1) {
        DBG1(DBG_LIB, "Error accepting connection:\n%s", strerror(errno));
        goto end;
    }
    plugin->comm.req = ret;
    plugin->is_pqsdk_on = true;

end:
    if (!plugin->is_pqsdk_on) {
        if (plugin->comm.fd) {
            close(plugin->comm.fd);
        }
        if (plugin->comm.req) {
            close(plugin->comm.req);
        }
    }
	// TODO: because of that plugin supports only one client
    lib->set(lib, "pqsdkd-connector-main", &plugin->comm);
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
	close(this->comm.fd);
	close(this->comm.req);
	if (this->comm.socket_path) {
		unlink(this->comm.socket_path);
		this->comm.socket_path = NULL;
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
        .comm = {
			.fd = 0,
			.req =0,
			.socket_path = 0
		},
    );

    if (!init_pqsdkd(this)) {
        DBG1(DBG_LIB, "PQSDK:PQSDKd initialization failed");
        return NULL;
    }

    return &this->public.plugin;
}
