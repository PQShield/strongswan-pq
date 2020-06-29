#ifndef PQSDKD_COMM_H_
#define PQSDKD_COMM_H_

#include <collections/linked_list.h>
#include <library.h>
#include <threading/mutex.h>

/**
 * PQSDKd communication context. Stores file descriptor
 * for listener and the one returned by accept().
 */
typedef struct comm_t {

  /**
   * Communitaction context identifier.
   */
  size_t id;

  /**
   * Path to PQSDKd socket, read from configuration file.
   */
  char *socket_path;

  /**
   * Stream object
   */
  stream_t *stream;

  /**
   * Indicates wether connection is currently in use.
   */
  bool is_used;
} comm_t;

/**
 * Adds communication context to the list.
 *
 * @param comm_list		List of usable communication
 *						contexts.
 * @param id 			Unique ID of communitaction context.
 * @param comm			Usable communication context.
 * @return				TRUE if added, FALSE if comm with ID
 *already exists
 */
bool comm_add(linked_list_t *comm_list, comm_t *comm);

/**
 * Finds communication context by ID.
 *
 * @param comm_list		List of usable communication
 *						contexts.
 * @param id 			Unique ID of communitaction context.
 * @return				Communication context or NULL if not
 *found.
 */
comm_t *comm_get_by_id(linked_list_t *comm_list, int id);

/**
 * Locks and returns next available communication context.
 *
 * @param comm_list		List of usable communication
 *						contexts.
 * @param id 			Unique ID of communitaction context.
 * @return				Communication context or NULL if non
 *available.
 */
comm_t *comm_lock_next(linked_list_t *comm_list);

/**
 * Mark communication context as free to use.
 *
 * @param comm_list		List of usable communication
 *						contexts.
 * @param id 			Unique ID of communitaction context.
 */
void comm_unlock(linked_list_t *comm_list, int id);

/**
 * Closes all connections and removes all communication contexts.
 *
 * @param l 	List of communication contexts.
 */
void comm_clean_list(linked_list_t *l);

#endif // PQSDKD_COMM_H_
