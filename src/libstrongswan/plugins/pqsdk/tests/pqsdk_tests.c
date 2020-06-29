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

#include "test_suite.h"
#include <library.h>
#include <time.h>
#include "pqtls/kem.h"
#include "pqsdkd/kem.h"

#ifdef USE_PQSDK_PQSDKD
#include "pqsdkd/comm.h"
#endif // USE_PQSDK_PQSDKD

const int count = 10;

typedef key_exchange_t* (*kem_creator_t)(key_exchange_method_t method);

// List of KEMs used by all of those tests
static int supported_KEMs[] = {
	KE_FRODO_SHAKE_L1,
	KE_FRODO_SHAKE_L3,
	KE_FRODO_SHAKE_L5,
	KE_KYBER_L1      ,
	KE_KYBER_L3      ,
	KE_KYBER_L5      ,
	KE_NTRU_HPS_L1   ,
	KE_NTRU_HRSS_L3  ,
	KE_SABER_L1      ,
	KE_SABER_L3      ,
	KE_SABER_L5      ,
	KE_RND5_5D_CCA_L1,
	KE_RND5_5D_CCA_L3,
	KE_RND5_5D_CCA_L5,
};

static kem_creator_t ctor = NULL;

START_TEST(test_pqsdk_roundtrip) {
	const key_exchange_method_t method = supported_KEMs[_i];
	chunk_t pk, ct, i_secret, r_secret;
	key_exchange_t *i_ke, *r_ke;
	struct timespec start, stop;
	int k;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	for (k = 0; k < count; k++) {
		// Initiator: create a key pair and return public key
		i_ke = (key_exchange_t*)ctor(method);
		ck_assert(i_ke);
		ck_assert(i_ke->get_method(i_ke) == method);
		ck_assert(i_ke->get_public_key(i_ke, &pk));

		// Responder: encapsulate with initiators public key
		r_ke = (key_exchange_t*)ctor(method);
		ck_assert(r_ke);
		ck_assert(r_ke->set_public_key(r_ke, pk));
		// get_public performs encapsulation and returns shared secret
		ck_assert(r_ke->get_public_key(r_ke, &ct));
		ck_assert(r_ke->get_shared_secret(r_ke, &r_secret));

		// Initiator: decapsulate
		ck_assert(i_ke->set_public_key(i_ke, ct));
		ck_assert(i_ke->get_shared_secret(i_ke, &i_secret));
		ck_assert(i_secret.len != 0);
		ck_assert_chunk_eq(i_secret, r_secret);

		/* cleanup */
		chunk_clear(&i_secret);
		chunk_clear(&r_secret);
		chunk_free(&pk);
		chunk_free(&ct);
		i_ke->destroy(i_ke);
		r_ke->destroy(r_ke);
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &stop);

	DBG0(DBG_LIB, "\n%d %N loops in %d ms", count,
				  key_exchange_method_names, method,
				  (stop.tv_nsec - start.tv_nsec) / 1000000 +
				  (stop.tv_sec - start.tv_sec) * 1000);
}
END_TEST

START_TEST(test_pqsdk_negative_unexpcted_input) {
	const key_exchange_method_t method = supported_KEMs[_i];
	chunk_t pk, ct, fake_pk, fake_ct, ss;
	key_exchange_t *i_ke, *r_ke;

	// unsupported KEM
	ck_assert(!ctor(KE_BIKE1_L1));
	// not a KEM
	ck_assert(!ctor(CURVE_25519));

	// generate public key
	i_ke = (key_exchange_t*)ctor(method);
	ck_assert(i_ke->get_public_key(i_ke, &pk));
	i_ke->destroy(i_ke);

	// generate ciphertext
	r_ke = (key_exchange_t*)ctor(method);
	ck_assert(r_ke->set_public_key(r_ke, pk));
	ck_assert(r_ke->get_public_key(r_ke, &ct));
	r_ke->destroy(r_ke);

	fake_pk = chunk_create((u_char*)malloc(pk.len), pk.len);
	fake_ct = chunk_create((u_char*)malloc(ct.len), ct.len);

	// try setting wrong length public key
	r_ke = (key_exchange_t*)ctor(method);
	fake_pk.len--;
	ck_assert(!r_ke->set_public_key(r_ke, fake_pk));
	ck_assert(!r_ke->get_shared_secret(r_ke, &ss));
	fake_pk.len=1;
	ck_assert(!r_ke->set_public_key(r_ke, fake_pk));
	ck_assert(!r_ke->get_shared_secret(r_ke, &ss));
	fake_pk.len=0;
	ck_assert(!r_ke->set_public_key(r_ke, fake_pk));
	ck_assert(!r_ke->get_shared_secret(r_ke, &ss));
	// check if it still works if correct public key is provided
	ck_assert(r_ke->set_public_key(r_ke, pk));
	ck_assert(r_ke->get_shared_secret(r_ke, &ss));
	r_ke->destroy(r_ke);
	chunk_free(&fake_pk);

	// try setting wrong length ciphertext
	i_ke = (key_exchange_t*)ctor(method);

	// sets i_ke into "initiator state"
	ck_assert(i_ke->get_public_key(i_ke, &fake_pk));

	fake_ct.len--; ck_assert(!i_ke->set_public_key(i_ke, fake_ct));
	fake_ct.len=1; ck_assert(!i_ke->set_public_key(i_ke, fake_ct));
	fake_ct.len=0; ck_assert(!i_ke->set_public_key(i_ke, fake_ct));
	i_ke->destroy(i_ke);

	chunk_free(&pk);
	chunk_free(&ct);
	chunk_free(&ss);
	chunk_free(&fake_ct);
	chunk_free(&fake_pk);
}
END_TEST

START_TEST(test_pqsdk_negative_wrong_shared_secret) {
	const key_exchange_method_t method = supported_KEMs[_i];
	chunk_t pk, ct, r_secret, i_secret, fake_ct;
	key_exchange_t *i_ke, *r_ke;

	// Initiator
	i_ke = (key_exchange_t*)ctor(method);
	ck_assert(i_ke->get_public_key(i_ke, &pk));

	// Responder: encapsulate with initiators public key
	r_ke = (key_exchange_t*)ctor(method);
	ck_assert(r_ke->set_public_key(r_ke, pk));
	ck_assert(r_ke->get_public_key(r_ke, &ct));
	ck_assert(r_ke->get_shared_secret(r_ke, &r_secret));
	ck_assert(!chunk_equals(r_secret, chunk_empty));

	// Partially change received ciphertext
	fake_ct = chunk_clone(ct);
	memset(fake_ct.ptr, 0xff, 14);
	*fake_ct.ptr = !(*fake_ct.ptr);

	// Initiator: decapsulate
	ck_assert(i_ke->set_public_key(i_ke, fake_ct));
	ck_assert(i_ke->get_shared_secret(i_ke, &i_secret));
	ck_assert(i_secret.len != 0);
	ck_assert(!chunk_equals(i_secret, r_secret));

	/* cleanup */
	chunk_clear(&i_secret);
	chunk_clear(&r_secret);
	chunk_free(&pk);
	chunk_free(&ct);
	chunk_free(&fake_ct);
	i_ke->destroy(i_ke);
	r_ke->destroy(r_ke);
}
END_TEST

#ifdef USE_PQSDK_PQTLS
static void setup_pqtls(void) {
	ctor = (kem_creator_t)pqtls_kem_create;
}
#endif

#ifdef USE_PQSDK_PQSDKD
static void setup_pqsdkd(void) {
	ctor = (kem_creator_t)pqsdkd_kem_create;
}
#endif

#ifdef USE_PQSDK_PQSDKD
START_TEST(test_pqsdkd_connect) {
	comm_t *el = NULL;
	linked_list_t *connection_list;

	connection_list = lib->get(lib, "pqsdkd-connectors-list");
	ck_assert(connection_list != NULL);
	el = comm_lock_next(connection_list);
	ck_assert(el != NULL);

	ck_assert(el->socket_path);
	ck_assert(el->stream);
	ck_assert(el->id != 0);
	ck_assert(el->is_used);
	comm_unlock(connection_list, el->id);

	// set t/o
	// force reconnect
	// check if reconnected
}
END_TEST

START_TEST(test_pqsdkd_comm) {
	linked_list_t *ltmp;
	comm_t *comm1 = (comm_t*)malloc(sizeof(*comm1));
	comm_t *comm2 = (comm_t*)malloc(sizeof(*comm2));

	ltmp = linked_list_create();
	comm1->id = 1;
	comm2->id = 2;
	comm1->stream = comm2 ->stream = NULL;
	ck_assert(ltmp->get_count(ltmp) == 0);
	ck_assert(comm_add(ltmp, comm1));
	ck_assert(ltmp->get_count(ltmp) == 1);
	ck_assert(!comm_add(ltmp, comm1));
	ck_assert(ltmp->get_count(ltmp) == 1);
	ck_assert(comm_add(ltmp, comm2));
	ck_assert(ltmp->get_count(ltmp) == 2);

	comm_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
	ck_assert((c1 = comm_lock_next(ltmp)));
	ck_assert((c2 = comm_lock_next(ltmp)));
	ck_assert(!(c3 = comm_lock_next(ltmp)));

	ck_assert(c1->is_used);
	ck_assert(c2->is_used);
	ck_assert(c1->id == 1);
	ck_assert(c2->id == 2);
	ck_assert(c1->id != c2->id);

	comm_unlock(ltmp, c2->id);
	c2 = NULL;
	ck_assert((c2 = comm_lock_next(ltmp)));
	ck_assert(c2->id == 2);

	comm_unlock(ltmp, c1->id);
	ck_assert((c1 = comm_get_by_id(ltmp, 1)));
	ck_assert(!(c3 = comm_get_by_id(ltmp, 3)));

	comm_clean_list(ltmp);
	ck_assert(ltmp->get_count(ltmp) == 0);
	ltmp->destroy(ltmp);
	ltmp = NULL;
	comm_clean_list(ltmp);
}
END_TEST
#endif

void tcase_add_cases_with_setup(Suite *s, void(*setup)(void)) {
	TCase *tc;

	tc = tcase_create("roundtrip");
	test_case_set_timeout(tc, 5);
	tcase_add_checked_fixture(tc, setup, NULL);
	tcase_add_loop_test(tc, test_pqsdk_roundtrip, 0, countof(supported_KEMs));
	suite_add_tcase(s, tc);

	tc = tcase_create("unexpected_input");
	tcase_add_checked_fixture(tc, setup, NULL);
	tcase_add_loop_test(tc, test_pqsdk_negative_unexpcted_input, 0, countof(supported_KEMs));
	suite_add_tcase(s, tc);

	tc = tcase_create("ensure_wrong_result_from_decaps_on_wrong_ct");
	tcase_add_checked_fixture(tc, setup, NULL);
	tcase_add_loop_test(tc, test_pqsdk_negative_wrong_shared_secret, 0, countof(supported_KEMs));
	suite_add_tcase(s, tc);

#ifdef USE_PQSDK_PQSDKD
	tc = tcase_create("connection");
	tcase_add_checked_fixture(tc, setup, NULL);
	tcase_add_loop_test(tc, test_pqsdkd_connect, 0, countof(supported_KEMs));
	tcase_add_test(tc, test_pqsdkd_comm);
	suite_add_tcase(s, tc);
#endif
}

Suite *pqsdk_pqtls_suite_create()
{
	Suite *s;

	s = suite_create("pqsdk");
#ifdef USE_PQSDK_PQTLS
	// test PQSDK:PQTLS
	tcase_add_cases_with_setup(s, setup_pqtls);
#endif
#ifdef USE_PQSDK_PQSDKD
	// test PQSDK:PQSDK
	tcase_add_cases_with_setup(s, setup_pqsdkd);
#endif

	return s;
}
