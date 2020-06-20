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
 * @defgroup pqsdkd_kem_ka pqsdkd_kem_ka
 * @{ @ingroup pqsdk_p
 */

#ifndef PQSDKD_KEM_H_
#define PQSDKD_KEM_H_

#include <crypto/key_exchange.h>

typedef struct pqsdkd_kem_t pqsdkd_kem_t;

/**
 * Post-quantum key exchange implementation supported
 * by PQSDKd.
 */
struct pqsdkd_kem_t {

  /**
   * Implements the key_exchange_t interface. Must be first
   * in the structure to allow casting.
   */
  key_exchange_t ke;

  /**
   * Public key
   */
  chunk_t pk;

  /**
   * Secret key
   */
  chunk_t sk;

  /**
   * Ciphertext
   */
  chunk_t ct;

  /**
   * Shared secret
   */
  chunk_t secret;
  /**
   * Indicates wethar shared secret was generated and is
   * available to use.
   */
  bool has_secret;
};

/**
 * Creates a new pqsdkd_kem_t object.
 *
 * @param method    QSKE mechanism number
 * @return          pqsdkd_kem_t object, NULL if not
 * supported
 */
pqsdkd_kem_t *pqsdkd_kem_create(key_exchange_method_t method);

#endif /** PQSDKD_KEM_H_ @}*/
