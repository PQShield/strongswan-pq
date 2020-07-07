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
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <crypto/key_exchange.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <library.h>
#include "kem.h"
#include "pq_message_lib.h"
#include "pqsdkd_plugin.h"
#include "comm.h"

#include "processing/jobs/callback_job.h"

#define CHECK_NZ(exp) \
	do { \
		if (!(exp)) { \
			DBG1(DBG_LIB, "%s:%d NULL pointer: %s\n", __FILE__, __LINE__, #exp); \
			goto end; \
		} \
	} while (0)

typedef struct private_pqsdkd_kem_t private_pqsdkd_kem_t;

/** Internal state used for indicating initiator/responder side of IKE */
typedef enum {
	/** KEM created */
	ACTION_CREATE =  1 << 0,
	/** peer public key set */
	ACTION_PUB_SET = 1 << 1,
	/** public key provided to the framework */
	ACTION_PUB_GET = 1 << 2,
} ex_action_t;

/** Flags indicating communication and data exchange state. */
typedef enum {
	// No action to be done
	EX_NONE	       = 0,
	// Data will be sent to PQSDKd
	EX_WANTS_WRITE = 1 << 0,
	// Expects to receive data from PQSDKd
	EX_WANTS_READ  = 1 << 1,
	// Must handle disconnection from PQSDKd
	EX_DISCONNECT  = 1 << 2,
	// More data exepcted. Keep on_write/on_read callback registered
	EX_KEEP        = 1 << 3,
	// Data exchange done. Unregister on_read/on_write callback.
	EX_UNREGISTER  = 1 << 4,
	// Communication function starts to wait for a signal from
	// on_read/on_write threads.
	EX_CAN_SIGNAL  = 1 << 5,
} ex_status_t;

/** Communication context between plugin and PQSDKd */
typedef struct pqsdkd_ctx_t {

	/** Condition variable signals message exchange is over */
	condvar_t *ex_cond;
	/** Mutex used for request/response synchronization*/
	mutex_t *ex_lock;
	/** Stores poitner to the request. Used by on_write */
	chunk_t req;
	/** Stores poitner to the request. Used by on_read */
	chunk_t rsp;
	/** Flags indicating operation state. */
	ex_status_t flags;
	/**
	 * Max amount of time read and write operation is allowed
	 * to take before ex_cond times out.
	 */
	int msg_ex_to;
	/** Number of bytes send or recived till now */
	size_t bytes_processed;
	/**
	 * Pointer to the communication context. Used by diconnect
	 * funciton.
	 */
	comm_t *comm;

} pqsdkd_ctx_t;

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
	comm_t *comm;
	/**
	 * Pre-allocated buffer for request header.
	 */
	chunk_t header_req;

	/**
	 * Pre-allocated buffer for response header.
	 */
	chunk_t header_rsp;

	/**
	 * Holds data needed for message exchange with PQSDKd.
	 */
	pqsdkd_ctx_t pqsdkd_ctx;

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

// Returns true if "flag" is set in the bitset "bits".
static inline bool is_set(unsigned int bits, unsigned int flag) {
	return (bits & flag) == flag;
}

/**
 *  Returns 0 on failure, otherwise data_len to read
 *  from the req socket.
 */
static int get_data_len(chunk_t header_rsp) {
	ResponseHeader rsp = {0};
	if (deserialize_response_header(header_rsp.ptr, &rsp)) {
		DBG1(DBG_LIB, "keygen: can't deserialize");
		return 0;
	}

	if (rsp.success) {
		DBG1(DBG_LIB, "keygen: wrong response from PQSDKd");
		return 0;
	}
	return rsp.data_len;
}

// Handles result received from do_write()/do_read()
static bool handle_result(ex_status_t status, pqsdkd_ctx_t *ctx) {
	switch(status) {
		case EX_KEEP:
			return TRUE;
		case EX_UNREGISTER:
			return FALSE;
		case EX_DISCONNECT:
			ctx->ex_lock->lock(ctx->ex_lock);
			ctx->flags = EX_NONE | EX_CAN_SIGNAL;
			ctx->ex_lock->unlock(ctx->ex_lock);

			ctx->comm->reconnect = true;
			ctx->ex_cond->signal(ctx->ex_cond);
			lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio((callback_job_cb_t)try_connect,
					ctx->comm, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_HIGH));
			return FALSE;
		default:
			DBG0(DBG_LIB, "unhandled event occured");
			/**
			 * Should never happen. Unregister callback,
			 * communicate() will generate an error.
			 */
			return FALSE;
	}
}

static ex_status_t do_write(pqsdkd_ctx_t *ctx, stream_t *stream) {
	ssize_t len;
	while (ctx->req.len > ctx->bytes_processed) {
		len = stream->write(stream,
			ctx->req.ptr + ctx->bytes_processed,
			ctx->req.len - ctx->bytes_processed,
			FALSE);

		if (len == 0) {
			DBG1(DBG_LIB, "pqsdkd: server disconnected: %s", strerror(errno));
			return EX_DISCONNECT;
		}

		if (len < 0) {
			if (errno == EWOULDBLOCK) {
				return EX_KEEP;
			}
            DBG1(DBG_LIB, "pqsdkd: write error: %s", strerror(errno));
			return EX_DISCONNECT;
		}
		ctx->bytes_processed += (size_t)len;
	}

	return EX_UNREGISTER;
}

/**
 * Process responses from PQSDKd
 */
CALLBACK(on_write, bool, pqsdkd_ctx_t *ctx, stream_t *stream) {
	bool wants_read;
	ex_status_t ret = EX_UNREGISTER;

	ctx->ex_lock->lock(ctx->ex_lock);
	if (!is_set(ctx->flags, EX_CAN_SIGNAL)) {
		ctx->ex_lock->unlock(ctx->ex_lock);
		return TRUE;
	}

	if (is_set(ctx->flags, EX_WANTS_WRITE)) {
		ret = do_write(ctx, stream);
		if (ret == EX_UNREGISTER) {
			ctx->flags &= ~EX_WANTS_WRITE;
			ctx->bytes_processed = 0;
		}
	}
	wants_read = is_set(ctx->flags, EX_WANTS_READ);
	ctx->ex_lock->unlock(ctx->ex_lock);

	// Don't signal if waiting for response
	if ((ret == EX_UNREGISTER) && !wants_read) {
		ctx->ex_cond->signal(ctx->ex_cond);
	}
	return handle_result(ret, ctx);
}

static ex_status_t do_read(pqsdkd_ctx_t *ctx, stream_t *stream) {
	ssize_t len;
	while (ctx->rsp.len > ctx->bytes_processed) {
		len = stream->read(stream,
			ctx->rsp.ptr + ctx->bytes_processed,
			ctx->rsp.len - ctx->bytes_processed,
			FALSE);

		if (len == 0) {
			DBG1(DBG_LIB, "pqsdkd: server disconnected: %s", strerror(errno));
			return EX_DISCONNECT;
		}

		if (len < 0) {
			if (errno == EWOULDBLOCK) {
				return EX_KEEP;
			}
			DBG1(DBG_LIB, "pqsdkd: read error: %s", strerror(errno));
			return EX_DISCONNECT;
		}
		ctx->bytes_processed += len;
	}
	return EX_UNREGISTER;
}

CALLBACK(on_read, bool, pqsdkd_ctx_t *ctx, stream_t *stream) {
	bool write_done;
	ex_status_t ret = EX_UNREGISTER;

	ctx->ex_lock->lock(ctx->ex_lock);
	if (!is_set(ctx->flags, EX_CAN_SIGNAL)) {
		ctx->ex_lock->unlock(ctx->ex_lock);
		return TRUE;
	}

	write_done = !is_set(ctx->flags, EX_WANTS_WRITE);

	// Don't read until write is finished
	if (is_set(ctx->flags, EX_WANTS_READ) && write_done) {
		ret = do_read(ctx, stream);
		if (ret == EX_UNREGISTER) {
			ctx->flags &= ~EX_WANTS_READ;
			ctx->bytes_processed = 0;
		}
	}

	ctx->ex_lock->unlock(ctx->ex_lock);
	if (ret == EX_UNREGISTER) {
		ctx->ex_cond->signal(ctx->ex_cond);
	}
	return handle_result(ret, ctx);
}

/**
 * Send req.len bytes to the c.req and read rsp.len just after.
 * Returns FALSE if communication error occured.
 */
static bool communicate(chunk_t rsp, const chunk_t req,
	stream_t *stream, pqsdkd_ctx_t *ctx) {

	bool ret;

	if (!stream) {
		DBG1(DBG_LIB, "Connection not available: scheduling reconnect.");
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio((callback_job_cb_t)try_connect,
				ctx->comm, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_HIGH));
		return FALSE;
	}

	ctx->bytes_processed = 0;
	ctx->flags = EX_NONE;
	if (req.len) ctx->flags |= EX_WANTS_WRITE;
	if (rsp.len) ctx->flags |= EX_WANTS_READ;
	if (ctx->flags == EX_NONE) return TRUE;

	if (is_set(ctx->flags, EX_WANTS_WRITE)) {
		ctx->req = req;
		stream->on_write(stream, on_write, ctx);
	}

	if (is_set(ctx->flags, EX_WANTS_READ)) {
		ctx->rsp = rsp;
		stream->on_read(stream, on_read, ctx);
	}

	ctx->ex_lock->lock(ctx->ex_lock);
	/**
	 * Both threads check if EX_CAN_SIGNAL is set before starting
	 * to send/receive data. Not having such a flag could cause
	 * a deadlock, because thread executing on_read/on_write could
	 * signal before communicate() calls timed_wait(). Hence the goal
	 * of this flag is to make sure that singal() is called AFTER
	 * timed_wait() is called.  The other way to avoid deadlock is to
	 * lock the ex_lock, before calling on_write/on_read, unfortunatelly
	 * in this causes another deadlock as on_write() may be executed
	 * before ex_lock is unlocked.
	 */
	ctx->flags |= EX_CAN_SIGNAL;
	ret = ctx->ex_cond->timed_wait(ctx->ex_cond, ctx->ex_lock, ctx->msg_ex_to);
	ctx->ex_lock->unlock(ctx->ex_lock);

	if (ret) {
		DBG1(DBG_LIB, "Communication timed out.");
	}
	return !ret;
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

	// unregister on_read and on_write
	if (this->comm->stream) {
		this->comm->stream->on_read(this->comm->stream, NULL, NULL);
		this->comm->stream->on_write(this->comm->stream, NULL, NULL);
	}
	this->comm = NULL;
	this->pqsdkd_ctx.ex_cond->destroy(this->pqsdkd_ctx.ex_cond);
	this->pqsdkd_ctx.ex_lock->unlock(this->pqsdkd_ctx.ex_lock);
	this->pqsdkd_ctx.ex_lock->destroy(this->pqsdkd_ctx.ex_lock);
	this->pqsdkd_ctx.comm = NULL;
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

		CHECK_NZ(communicate(this->header_rsp, this->header_req,
			this->comm->stream, &this->pqsdkd_ctx));
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		// get keypair
		ch = chunk_alloc(sz);
		CHECK_NZ(ch.ptr);

		CHECK_NZ(communicate(ch, chunk_empty, this->comm->stream,
			&this->pqsdkd_ctx));
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

		CHECK_NZ(communicate(chunk_empty, this->header_req,
			this->comm->stream,	&this->pqsdkd_ctx));

		CHECK_NZ(communicate(this->header_rsp, value, this->comm->stream,
			&this->pqsdkd_ctx));
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		ch = chunk_alloc(sz);
		CHECK_NZ(ch.ptr);

		CHECK_NZ(communicate(ch, chunk_empty, this->comm->stream,
			&this->pqsdkd_ctx));
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
		CHECK_NZ(communicate(chunk_empty, this->header_req,
			this->comm->stream,	&this->pqsdkd_ctx));
		CHECK_NZ(communicate(this->header_rsp, ch, this->comm->stream,
			&this->pqsdkd_ctx));
		chunk_clear(&ch);

		// get shared secret
		sz = get_data_len(this->header_rsp);
		CHECK_NZ(sz);

		this->public.secret = chunk_alloc(sz);
		CHECK_NZ(this->public.secret.ptr);

		CHECK_NZ(communicate(this->public.secret, chunk_empty,
			this->comm->stream,	&this->pqsdkd_ctx));
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
	int *message_exchange_to;

	conn_list = lib->get(lib, "pqsdkd-connectors-list");
	message_exchange_to = lib->get(lib, "message-exchange-timeout");
	pqsdkd_meth_id = find_pqsdk_kem_id(ike_meth_id);

	if (pqsdkd_meth_id == -1) {
		DBG1(DBG_LIB, "Method [%d] not supported", ike_meth_id);
		return NULL;
	}

	if (!conn_list) {
		DBG1(DBG_LIB, "Internal error: connection list not found");
		return NULL;
	}

	if (!message_exchange_to) {
		DBG1(DBG_LIB, "Message exchange must be a positivie number > 0");
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
		.pqsdkd_ctx = {
			.ex_cond = condvar_create(CONDVAR_TYPE_DEFAULT),
			.ex_lock = mutex_create(MUTEX_TYPE_DEFAULT),
			.rsp = NULL,
			.req = NULL,
			.msg_ex_to = *message_exchange_to,
		},
		.header_req = chunk_alloc(get_serialized_request_header_size()),
		.header_rsp = chunk_alloc(get_serialized_response_header_size()),
		.connection_list = conn_list,
		.comm = comm_lock_next(conn_list),
	);
	this->pqsdkd_ctx.comm = this->comm;

	if (!this->comm) {
		DBG1(DBG_LIB, "No communication context available");
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
