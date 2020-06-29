#include <utils/debug.h>
#include <library.h>

#include "comm.h"

/**
 * Mutex synchronizing access to the connection_list.
 */
mutex_t *connection_list_mutex = NULL;

/**
 * List containing PQSDKd connection contexts.
 */
linked_list_t *connection_list = NULL;

static inline comm_t* comm_get_by_id_unlocked(linked_list_t *l, int id) {
	enumerator_t *it;
	comm_t *el;

	it = l->create_enumerator(l);
	while(it->enumerate(it, &el)) {
		if (el->id == id) {
			it->destroy(it);
			return el;
		}
	}
	it->destroy(it);
	return NULL;
}

bool comm_add(linked_list_t *l, comm_t *c) {
	comm_t *el;
	connection_list_mutex->lock(connection_list_mutex);
	el = comm_get_by_id_unlocked(l, c->id);
	if (!el) {
		c->is_used = FALSE;
		l->insert_last(l, c);
	}
	connection_list_mutex->unlock(connection_list_mutex);
	return el?FALSE:TRUE;
}

comm_t* comm_lock_next(linked_list_t *l) {
	comm_t *el = NULL, *eltmp;
	enumerator_t *it;

	connection_list_mutex->lock(connection_list_mutex);
	it = l->create_enumerator(l);

	while(it->enumerate(it, &el)) {
		if (!el->is_used) {
			el->is_used = TRUE;
			break;
		}
		el = NULL;
	}
	it->destroy(it);
	connection_list_mutex->unlock(connection_list_mutex);
	return el;
}

void comm_unlock(linked_list_t *l, int id) {
	comm_t *el = NULL;

	connection_list_mutex->lock(connection_list_mutex);
	if ((el = comm_get_by_id_unlocked(l, id))) {
		el->is_used = FALSE;
	}
	connection_list_mutex->unlock(connection_list_mutex);
}

comm_t* comm_get_by_id(linked_list_t *l, int id) {
	comm_t *el = NULL;
	connection_list_mutex->lock(connection_list_mutex);
	el = comm_get_by_id_unlocked(l, id);
	connection_list_mutex->unlock(connection_list_mutex);
	return el;
}

void comm_clean_list(linked_list_t *l) {
	comm_t *el;

	if (!l) {
		return;
	}

	connection_list_mutex->lock(connection_list_mutex);
	// close connections
	while (l->remove_last(l, (void**)&el) == SUCCESS) {
		if (el->stream) {
			el->stream->destroy(el->stream);
		}
		free(el);
	}
	connection_list_mutex->unlock(connection_list_mutex);
}
