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

#include <openssl/engine.h>

#include <plugins/plugin_feature.h>
#include <utils/debug.h>

#include "pqsdk_pqtls_plugin.h"
#include "kem.h"

#define PQTLS_ENGINE_NAME "pqtls"

typedef struct private_pqsdk_pqtls_plugin_t private_pqsdk_pqtls_plugin_t;

struct private_pqsdk_pqtls_plugin_t {

    /**
     * Public interface for the plugin. Always
     * must go first.
     */
    pqsdk_pqtls_plugin_t public;

    /**
     * Handle to PQSDK implemented as OpenSSL ENGINE.
     */
    ENGINE *engine;

    /**
     * Indicates weather PQSDK is initialized.
     */
    bool is_pqsdk_on;
};


static ENGINE *try_load_engine(const char *engine) {
  ENGINE *e = ENGINE_by_id("dynamic");

  if (!e) {
    return NULL;
  }

  if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0) ||
      !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
      ENGINE_free(e);
      e = NULL;
  }
  return e;
}

static int init_pqsdk(private_pqsdk_pqtls_plugin_t *plugin) {
    if (plugin->is_pqsdk_on) {
        // already initialized
        return 1;
    }

    if (!ERR_load_crypto_strings()) {
        DBG1(DBG_LIB, "Internal error");
        return 0;
    }

    if (!OPENSSL_init_crypto(
            OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC, NULL)) {
        DBG1(DBG_LIB, "OPENSSL_init_crypto");
        goto err;
    }

    if (!(plugin->engine = ENGINE_by_id(PQTLS_ENGINE_NAME))
		&& !(plugin->engine = try_load_engine(PQTLS_ENGINE_NAME))) {
            DBG1(DBG_LIB, "Invalid engine: " PQTLS_ENGINE_NAME);
            goto err;
    }

    if (!ENGINE_set_default(plugin->engine, ENGINE_METHOD_ALL)) {
        DBG1(DBG_LIB, "Binding OpenSSL methods to " PQTLS_ENGINE_NAME " failed");
        goto err;
    }

    DBG1(DBG_LIB, "Engine \"%s\" set.\n", ENGINE_get_id(plugin->engine));
    ERR_clear_error();
    plugin->is_pqsdk_on = true;

err:
	if (!plugin->is_pqsdk_on && plugin->engine) {
		ENGINE_free(plugin->engine);
		ERR_free_strings();
	}
    return (int)plugin->is_pqsdk_on;
}

static void release_engine(private_pqsdk_pqtls_plugin_t *plugin) {
    if (plugin->engine) {
        ENGINE_free(plugin->engine);
        ERR_free_strings();
    }
    plugin->is_pqsdk_on = false;
}

METHOD(plugin_t, get_name, char*,
    private_pqsdk_pqtls_plugin_t *this)
{
    return "pqsdk-pqtls";
}

METHOD(plugin_t, get_features, int,
    private_pqsdk_pqtls_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        PLUGIN_REGISTER(KE, pqtls_kem_create),
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
    private_pqsdk_pqtls_plugin_t *this)
{
    release_engine(this);
    free(this);
}

plugin_t *pqsdk_pqtls_plugin_create()
{
    private_pqsdk_pqtls_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );

    if (!init_pqsdk(this)) {
        DBG1(DBG_LIB, "PQSDK:PQTLS initialization failed");
        return NULL;
    }

    return &this->public.plugin;
}
