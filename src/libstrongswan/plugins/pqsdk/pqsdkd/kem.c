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
#include <sys/socket.h>
#include <unistd.h>

#include <crypto/key_exchange.h>
#include <library.h>
#include "kem.h"
#include "pq_message_lib.h"
#include "pqsdkd_plugin.h"
#include "comm.h"

#define CHECK_NZ(exp) \
	do { \
		if (!(exp)) { \
			DBG1(DBG_LIB, "NULL pointer: %s\n", #exp); \
			goto end; \
		} \
	} while (0)

typedef struct private_pqsdkd_kem_t private_pqsdkd_kem_t;

// internal state used for indicating initiator/responder side of IKE
typedef enum {
	// KEM created
	ACTION_CREATE =  1 << 0,
	// peer public key set
	ACTION_PUB_SET = 1 << 1,
	// public key provided to the framework
	ACTION_PUB_GET = 1 << 2,
} ex_action_t;

typedef struct private_pqsdkd_kem_t {
	/**
	 * Public interface for PQSDK.
	 */
	struct pqsdkd_kem_t public;

	/**
	 * IKEv2 key exchange method
	 */
	int ike_meth_id;

	/**
	 * PQSDKd key exchange method
	 */
	int pqsdkd_meth_id;

	/*
	 * Stores actions done by a plugin indicating
	 * IKE connection state (responder/initiator).
	 */
	ex_action_t state;

	/**
	* Communication context PQSDK:PQSDKD.
	*/
	struct comm_t *comm;

	/**
	 * Pre-allocated buffer for request header.
	 */
	chunk_t header_req;

	/**
	 * Pre-allocated buffer for response header.
	 */
	chunk_t header_rsp;

	/**
	 * Pointer to the PQSDKd connection list
	 */
	linked_list_t *connection_list;
} private_pqsdkd_kem_t;

// Change state of the plugin if needed
static void change_state(private_pqsdkd_kem_t *ka, ex_action_t action) {
	if (ka->state == ACTION_CREATE) {
		ka->state |= action;
	}
}

// Returns true if plugin is running on IKE responder side.
static bool is_responder(private_pqsdkd_kem_t *ka, ex_action_t action) {
	change_state(ka, action);
	return ka->state == (ACTION_CREATE | ACTION_PUB_SET);
}

/**
 *  Returns 0 on failure, otherwise data_len to read
 *  from the req socket.
 */
static int get_data_len(chunk_t header_rsp) {
	ResponseHeader rsp = {0};
	if (deserialize_response_header(header_rsp.ptr, &rsp)) {
		DBG1(DBG_LIB, "keygen: can't deserialize\n");
		return 0;
	}

	if (rsp.success) {
		DBG1(DBG_LIB, "keygen: can't deserialize\n");
		return 0;
	}
	return rsp.data_len;
}

/**
 * Send req.len bytes to the c.req and read rsp.len just after.
 * This function will block.
 */
static int exchng(chunk_t rsp, const struct comm_t *c, const chunk_t req) {
	if (!c->stream->write_all(c->stream, req.ptr, req.len)) {
		return FALSE;
	}
	if (!c->stream->read_all(c->stream, rsp.ptr, rsp.len)) {
		return FALSE;
	}

	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_pqsdkd_kem_t *this)
{
	return this->ike_meth_id;
}

METHOD(key_exchange_t, destroy, void,
	private_pqsdkd_kem_t *this)
{
	chunk_free(&this->public.ct);
	chunk_free(&this->public.pk);
	chunk_clear(&this->public.sk);
	chunk_clear(&this->public.secret);
	if (this->comm) {
		comm_unlock(this->connection_list, this->comm->id);
	}
	this->comm = NULL;
	free(this);
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_pqsdkd_kem_t *this, chunk_t *secret)
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
	private_pqsdkd_kem_t *this, chunk_t *value) {

	unsigned char *pk = NULL, *sk = NULL;
	size_t sksz, pksz;
	chunk_t ch = chunk_empty;
	size_t sz = 0;
	bool ret = FALSE;

	if (!is_responder(this, ACTION_PUB_GET)) {
		CHECK_NZ(!serialize_request_header(this->header_req.ptr,
			this->header_req.len, 0, 0, this->pqsdkd_meth_id, KeypairGeneration));

		CHECK_NZ(exchng(this->header_rsp, this->comm, this->header_req));
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		// get keypair
		ch = chunk_alloc(sz);
		CHECK_NZ(ch.ptr);

		CHECK_NZ(exchng(ch, this->comm, chunk_empty));
		CHECK_NZ(!destructure_two_entries(ch.ptr, ch.len, &sksz, &pksz,
			(const unsigned char**)&sk, (const unsigned char**)&pk));
		this->public.pk = chunk_clone(chunk_create(pk, pksz));
		this->public.sk = chunk_clone(chunk_create(sk, sksz));
		*value = chunk_clone(this->public.pk);
	} else {
		*value = chunk_clone(this->public.ct);
	}
	ret = TRUE;

end:
	chunk_free(&ch);
	if (!ret) {
		chunk_free(&this->public.ct);
		chunk_free(&this->public.pk);

		// Heders and sk may contain sensitive data
		chunk_clear(&this->public.sk);
		chunk_clear(&this->header_req);
		chunk_clear(&this->header_rsp);
	}
	return ret;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_pqsdkd_kem_t *this, chunk_t value) {
	unsigned char *ct = NULL, *ss = NULL;
	size_t ctsz, sssz;
	size_t sz = 0;
	chunk_t ch = chunk_empty;
	bool ret = FALSE;

	if (is_responder(this, ACTION_PUB_SET)) {
		CHECK_NZ(!serialize_request_header(this->header_req.ptr,
			this->header_req.len, 0, value.len,
			this->pqsdkd_meth_id, Encapsulation));

		CHECK_NZ(exchng(chunk_empty, this->comm, this->header_req));
		CHECK_NZ(exchng(this->header_rsp, this->comm, value));
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		ch = chunk_alloc(sz);
		CHECK_NZ(ch.ptr);

		CHECK_NZ(exchng(ch, this->comm, chunk_empty));
		CHECK_NZ(!destructure_two_entries(ch.ptr, ch.len, &sssz, &ctsz,
			(const unsigned char**)&ss, (const unsigned char**)&ct));

		this->public.ct = chunk_clone(chunk_create(ct, ctsz));
		this->public.secret = chunk_clone(chunk_create(ss, sssz));
	} else {
		// request decapsulation
		sz = structure_two_entries_length(this->public.sk.len, value.len);
		CHECK_NZ(!serialize_request_header(this->header_req.ptr,
			this->header_req.len, 0, sz,
			this->pqsdkd_meth_id, Decapsulation));
		ch = chunk_alloc(sz);
		CHECK_NZ(ch.ptr);

		structure_two_entries(ch.ptr, this->public.sk.len, value.len,
			this->public.sk.ptr, value.ptr);
		CHECK_NZ(exchng(chunk_empty, this->comm, this->header_req));
		CHECK_NZ(exchng(this->header_rsp, this->comm, ch));
		chunk_clear(&ch);

		// get shared secret
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		this->public.secret = chunk_alloc(sz);
		CHECK_NZ(this->public.secret.ptr);

		CHECK_NZ(exchng(this->public.secret, this->comm, chunk_empty));
	}
	this->public.has_secret = TRUE;
	ret = TRUE;
end:
	chunk_free(&ch);
	if (!ret) {
		// ensure shared secret is wiped out
		chunk_clear(&this->public.secret);
		chunk_free(&this->public.ct);
		this->public.has_secret = FALSE;
	}
	return ret;
}

static int find_pqsdk_kem_id(key_exchange_method_t ike_method_id) {
	static const struct {
		key_exchange_method_t ike_method_id;
		unsigned int pqsdk_id;
	} map[] = {
		{ KE_FRODO_SHAKE_L1, FRODO640         },
		{ KE_FRODO_SHAKE_L3, FRODO976         },
		{ KE_FRODO_SHAKE_L5, FRODO1344        },
		{ KE_NTRU_HPS_L1,    NTRU_HPS_2048509 },
		{ KE_NTRU_HRSS_L3,   NTRU_HRSS_701    },
		{ KE_RND5_5D_CCA_L1, RND5_1CCA_5D     },
		{ KE_RND5_5D_CCA_L3, RND5_3CCA_5D     },
		{ KE_RND5_5D_CCA_L5, RND5_5CCA_5D     },
		{ KE_KYBER_L1,       KYBER_512        },
		{ KE_KYBER_L3,       KYBER_768        },
		{ KE_KYBER_L5,       KYBER_1024       },
		{ KE_SABER_L1,       SABER_LIGHT      },
		{ KE_SABER_L3,       SABER            },
		{ KE_SABER_L5,       SABER_FIRE       },
	};

	for(size_t i=0; i<countof(map); i++) {
		if (map[i].ike_method_id == ike_method_id) {
			return map[i].pqsdk_id;
		}
	}
	return -1;
}

struct pqsdkd_kem_t *pqsdkd_kem_create(key_exchange_method_t ike_meth_id)
{
	struct private_pqsdkd_kem_t *this;
	int pqsdkd_meth_id;
	linked_list_t *conn_list;

	conn_list = lib->get(lib, "pqsdkd-connectors-list");
	pqsdkd_meth_id = find_pqsdk_kem_id(ike_meth_id);

	if (pqsdkd_meth_id == -1) {
		DBG1(DBG_LIB, "Method [%d] not supported", ike_meth_id);
		return NULL;
	}

	if (!conn_list) {
		DBG1(DBG_LIB, "Internal error: connection list not found");
		return NULL;
	}

	// map method to name used by PQSDK
	INIT(this,
		.public = {
			.ke = {
				.get_method = _get_method,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_shared_secret = _get_shared_secret,
				.destroy = _destroy,
			},
			.ct = chunk_empty,
			.secret = chunk_empty,
			.has_secret = TRUE,
		},
		.ike_meth_id = ike_meth_id,
		.pqsdkd_meth_id = pqsdkd_meth_id,
		.state = ACTION_CREATE,
		.header_req = chunk_alloc(get_serialized_request_header_size()),
		.header_rsp = chunk_alloc(get_serialized_response_header_size()),
		.connection_list = conn_list,
		.comm = comm_lock_next(conn_list),
	);

	// OZAPTF: implement waiting. How long to wait
	if (!this->comm) {
		DBG1(DBG_LIB, "Waiting for available connection\n");
		return NULL;
	}

	if (!this->header_req.ptr || !this->header_rsp.ptr) {
		DBG1(DBG_LIB, "KEM initialization failed\n");
		chunk_free(&this->header_req);
		chunk_free(&this->header_rsp);
		return NULL;
	}

	return &this->public;
}
