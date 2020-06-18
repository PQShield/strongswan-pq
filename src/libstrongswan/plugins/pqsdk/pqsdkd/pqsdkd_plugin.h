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
 * @defgroup pqsdkd_p pqsdk
 * @ingroup plugins
 *
 * @defgroup pqsdkd_plugin pqsdkd_plugin
 * @{ @ingroup pqsdkd_p
 */

#ifndef PQSDKD_PLUGIN_H_
#define PQSDKD_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pqsdkd_plugin_t pqsdkd_plugin_t;

/**
 * The plugin adds support for post-quantum KEMs. The implementation
 * of KEMs is provided by PQShield's PQSDKd daemon.
 */
struct pqsdkd_plugin_t {

  /**
   * implements plugin interface
   */
  plugin_t plugin;
};

/**
 * PQSDKd communication context. Stores file descriptor
 * for listener and the one returned by accept().
 */
typedef struct comm_t {
  /**
   * Path to PQSDKd socket, read from configuration file.
   */
  const char* socket_path;

  /**
   * Listen socket.
   */
  int fd;

  /**
   * Acceptor socket used to send requests to PQSDKd
   */
  int req;
} comm_t;

#endif /** PQSDKD_PLUGIN_H_ @}*/
