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

/**
 * @defgroup pqsdk_p pqsdk
 * @ingroup plugins
 *
 * @defgroup pqsdk_plugin pqsdk_plugin
 * @{ @ingroup pqsdk_p
 */

#ifndef PQSDK_PLUGIN_H_
#define PQSDK_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pqsdk_pqtls_plugin_t pqsdk_pqtls_plugin_t;

/**
 * The plugin adds support for post-quantum KEMs. The implementation
 * of KEMs is provided by PQShield's PQSDK library. The PQSDK itself
 * is implemented in a form of OpenSSL ENGINE.
 */
struct pqsdk_pqtls_plugin_t {

  /**
   * implements plugin interface
   */
  plugin_t plugin;
};

#endif /** PQSDK_PLUGIN_H_ @}*/
