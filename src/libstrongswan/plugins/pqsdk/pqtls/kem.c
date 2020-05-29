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

#include <string.h>
#include <openssl/evp.h>
#include <crypto/key_exchange.h>
#include "kem.h"


// Returns size of the shared secret in the composite key exchange
#define EVP_PKEY_CTRL_PQTLS_GET_SS_SIZE 100 + 0
// Returns size of the ciphertext in the composite key exchange
#define EVP_PKEY_CTRL_PQTLS_GET_CT_SIZE 100 + 1

// In case exp is not zero, it produces error trace and goes to 'end'
#define CHECK_NZ(exp)\
	do {\
		if (!(exp)) {\
			DBG1(DBG_LIB, "NULL pointer: %s\n", #exp);\
			goto end;\
		}\
	} while (0)

// Checks if call to OpenSSL was succesfull and go to 'end' if not
#define CHECK_CALL(exp)	\
	do {	\
		int code = (exp);	\
		if ((code)<=0) {	\
			DBG1(DBG_LIB, "Call %s returned with %d\n", #exp, code);\
			goto end;	\
		}	\
	} while (0)

typedef struct private_pqsdk_pqtls_kem_t private_pqsdk_pqtls_kem_t;

// internal state used for indicating initiator/responder side of IKE
typedef enum {
	// KEM created
	ACTION_CREATE =  1 << 0,
	// peer public key set
	ACTION_PUB_SET = 1 << 1,
	// public key provided to the framework
	ACTION_PUB_GET = 1 << 2,
} ex_action_t;

typedef struct private_pqsdk_pqtls_kem_t {
	/**
	 * Public interface for PQSDK.
	 */
	struct pqsdk_kem_t public;

	/**
	 * Key exchange method
	 */
	key_exchange_method_t method;

	/**
	 * PQSDK internal ID of a KEM algorithm
	 */
	int nid;

	/*
	 * Stores actions done by a plugin indicating
	 * IKE connection state (responder/initiator).
	 */
	ex_action_t state;
} private_pqsdk_pqtls_kem_t;

// Change state of the plugin if needed
static void change_state(private_pqsdk_pqtls_kem_t *ka, ex_action_t action) {
	if (ka->state == ACTION_CREATE) {
		ka->state |= action;
	}
}

// Returns true if plugin is running on IKE responder side.
static bool is_responder(private_pqsdk_pqtls_kem_t *ka, ex_action_t action) {
	change_state(ka, action);
	return ka->state == (ACTION_CREATE | ACTION_PUB_SET);
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_pqsdk_pqtls_kem_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, destroy, void,
	private_pqsdk_pqtls_kem_t *this)
{
	chunk_free(&this->public.secret);
	chunk_free(&this->public.ct);
	EVP_PKEY_free(this->public.key);
	free(this);
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_pqsdk_pqtls_kem_t *this, chunk_t *secret)
{
	if (!this->public.has_secret) {
		return FALSE;
	}
	*secret = chunk_clone(this->public.secret);
	return TRUE;
}

/**
 * On the initiator side, the get_public_key is a first
 * function called during key agreement (KEM). Hence, in this
 * case function will create ephemeral keypair before returning,
 * public key. On the responder side, we assume that a public
 * key (ciphertext) has alreaday been set by set_public_key
 * and hence we simply return the buffer.
 */
METHOD(key_exchange_t, get_public_key, bool,
	private_pqsdk_pqtls_kem_t *this, chunk_t *value)
{
	EVP_PKEY_CTX *ctx = NULL;
	bool ret = FALSE;
	size_t tmp = 0;

	if (!is_responder(this, ACTION_PUB_GET)) {
		ctx = EVP_PKEY_CTX_new_id(this->nid, 0);
		CHECK_NZ(ctx);
		CHECK_CALL(
			EVP_PKEY_keygen_init(ctx));
		CHECK_CALL(
			EVP_PKEY_keygen(ctx, &this->public.key));
		CHECK_NZ(
			this->public.key);

		CHECK_CALL(
			EVP_PKEY_get_raw_public_key(
				this->public.key, NULL, &tmp));
		this->public.ct = chunk_alloc(tmp);
		CHECK_NZ(this->public.ct.ptr);
		// reuse this->public.ct variable
		CHECK_CALL(
			EVP_PKEY_get_raw_public_key(this->public.key,
				this->public.ct.ptr, &tmp));
	}
	*value = chunk_clone(this->public.ct);
	ret = TRUE;
end:
	if(ctx) {
		EVP_PKEY_CTX_free(ctx);
	}
	return ret;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_pqsdk_pqtls_kem_t *this, chunk_t value)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;
	size_t tmp = 0;
	chunk_t buf = chunk_empty;
	bool ret = FALSE;

	if (is_responder(this, ACTION_PUB_SET)) {
		ctx = EVP_PKEY_CTX_new_id(this->nid, 0);
		CHECK_NZ(ctx);
		CHECK_CALL(
			EVP_PKEY_encrypt_init(ctx));

		// allocate buffers for shared secret and ciphertext
		CHECK_CALL(
			EVP_PKEY_CTX_ctrl(ctx,
				-1,
				EVP_PKEY_OP_ENCRYPT,
				EVP_PKEY_CTRL_PQTLS_GET_CT_SIZE,
				0,
				(void*)&tmp));
		// reuse ct variable
		this->public.ct = chunk_alloc(tmp);
		CHECK_NZ(this->public.ct.ptr);
		CHECK_CALL(
			EVP_PKEY_CTX_ctrl(ctx,
				-1,
				EVP_PKEY_OP_ENCRYPT,
				EVP_PKEY_CTRL_PQTLS_GET_SS_SIZE,
				0,
				(void*)&tmp));
		this->public.secret = chunk_alloc(tmp);
		CHECK_NZ(this->public.secret.ptr);

		// Encapsulation
		key = EVP_PKEY_new_raw_public_key(this->nid, 0,
			value.ptr, value.len);
		CHECK_CALL(
			EVP_PKEY_encrypt(ctx, 0, &tmp, value.ptr, value.len));
		CHECK_NZ(
			tmp <= this->public.secret.len + this->public.ct.len);
		buf = chunk_alloc(tmp);
		CHECK_CALL(
			EVP_PKEY_encrypt(ctx, buf.ptr, &tmp, value.ptr, value.len));

		memcpy(this->public.secret.ptr, buf.ptr, this->public.secret.len);
		memcpy(this->public.ct.ptr,
			buf.ptr + this->public.secret.len, this->public.ct.len);
	} else {
		ctx = EVP_PKEY_CTX_new(this->public.key, NULL);
		CHECK_NZ(ctx);
		CHECK_CALL(
			EVP_PKEY_decrypt_init(ctx));

		CHECK_CALL(
			EVP_PKEY_decrypt(ctx, 0, &tmp, value.ptr, value.len));
		this->public.secret = chunk_alloc(tmp);
		CHECK_NZ(this->public.secret.ptr);
		CHECK_CALL(
			EVP_PKEY_decrypt(ctx, this->public.secret.ptr, &tmp,
				value.ptr, value.len));
	}
	this->public.has_secret = TRUE;
	ret = TRUE;
end:
	chunk_free(&buf);
	if (!ret) {
		// ensure shared secret is wiped out
		chunk_clear(&this->public.secret);
		chunk_free(&this->public.ct);
		this->public.has_secret = FALSE;
	}
	if (key) {
		EVP_PKEY_free(key);
	}
	if(ctx) {
		EVP_PKEY_CTX_free(ctx);
	}
	return ret;
}

struct pqsdk_kem_t *pqsdk_kem_create(key_exchange_method_t method)
{
	struct private_pqsdk_pqtls_kem_t *this;
	int nid = NID_undef;

	static const struct {
		key_exchange_method_t nid;
		const char* sid;
	} map[] = {
		{ KE_FRODO_SHAKE_L1, "FRODO640"         },
		{ KE_FRODO_SHAKE_L3, "FRODO976"         },
		{ KE_FRODO_SHAKE_L5, "FRODO1344"        },
		{ KE_NTRU_HPS_L1,    "NTRU_HPS_2048509" },
		{ KE_NTRU_HRSS_L3,   "NTRU_HRSS_701"    },
		{ KE_RND5_5D_CCA_L1, "RND5_1CCA_5D"     },
		{ KE_RND5_5D_CCA_L3, "RND5_3CCA_5D"     },
		{ KE_RND5_5D_CCA_L5, "RND5_5CCA_5D"     },
		{ KE_KYBER_L1,       "KYBER_512"        },
		{ KE_KYBER_L3,       "KYBER_768"        },
		{ KE_KYBER_L5,       "KYBER_1024"       },
		{ KE_SABER_L1,       "SABER_LIGHT"      },
		{ KE_SABER_L3,       "SABER"            },
		{ KE_SABER_L5,       "SABER_FIRE"       },
	};

	// map method to name used by PQSDK
	for (int i=0; i<countof(map); i++) {
		if (map[i].nid == method) {
			nid = OBJ_sn2nid(map[i].sid);
		}
	}

	if (!nid) {
		DBG1(DBG_IKE, "Unsupported KEM '%d'", method);
		return NULL;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_method = _get_method,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_shared_secret = _get_shared_secret,
				.destroy = _destroy,
			},
			.key = NULL,
			.ct = chunk_empty,
			.secret = chunk_empty,
			.has_secret = TRUE,
		},
		.method = method,
		.state = ACTION_CREATE,
		.nid = nid,
	);
	return &this->public;
}
