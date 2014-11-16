/*
 * qipc.c
 *
 *  Created on: 24-Oct-2014
 *      Author: matrix
 */

#include "pm.h"
#include "mproc.h"
#include <stdio.h>

/**
 *	Delivers notification to a calling process (CALLNR REQNOTIFY 79)
 *
 *Incoming IPC Message format:
 *  m_in.m10_i1 = Sender id requesting for Notification
 */

int do_mqreqnotify() {
	int req_no;
	pid_t receiver_pid;

	register struct mproc *rmp = mp;
	req_no = m_in.m10_i1;
	receiver_pid = rmp->mp_pid;
	printf("\nProcess %d has requested for notification", receiver_pid);

	if (notifier_count == QIPC_MAX_NOTIFIER_COUNT) {
		printf("\nError: Maximum capacity count reached");
		return 0;
	}

	g_arrNotificationPID[notifier_count][0] = receiver_pid;
	g_arrNotificationPID[notifier_count][1] = req_no;
	notifier_count++;
	return 1;
}

/**
 * Add or Remove users who can define queue permissions	(CALLNR ADDAUTHUSERS 108)
 *Incoming IPC Message format:
 *  m_in.m11_i1 = UID or GID
 *  m_in.m11_i2 = is it uid (1) or gid (0)
 *  m_in.m11_i3 = Add (1) or remove (0) this user
 */
int do_auth_users() {
	register struct mproc *rmp = mp;

	if (rmp->mp_effuid != 0) {
		printf(
				"\nERROR: New admin users/groups can only be added/deleted by 'root' user.");
		return UNAUTHORIZED_OP;
	}

	if (m_in.m11_i3 == 1) {
		//Add
		if (m_in.m11_i2 == 1) {
			//Add new uid
			return addNewAdminUser(m_in.m11_i1);
		} else if (m_in.m11_i2 == 0) {
			//Add new gid
			return addNewAdminGroup(m_in.m11_i1);
		}
	} else if (m_in.m11_i3 == 0) {
		//Delete
		if (m_in.m11_i2 == 1) {
			//Delete uid
			return deleteAdminUser(m_in.m11_i1);
		} else if (m_in.m11_i2 == 0) {
			//Delete gid
			return deleteAdminGroup(m_in.m11_i1);
		}
	}

	return 1;
}

/**
 * Add or Remove user permissions to queues (CALLNR AUTHPERM 109)
 * Incoming IPC Message format:
 *  m_in.m11_i1 = UID or GID
 *  m_in.m11_i2 = is it uid (1) or gid (0)
 *  m_in.m11_i3 = Permissions
 */
int do_auth_perm_secure() {
	register struct mproc *rmp = mp;

	if (!(isUserAdmin(rmp->mp_effuid) || isGroupAdmin(rmp->mp_effgid))) {
		printf(
				"\nERROR: Queue Authorization permissions can only be altered by admin users or groups");
		return UNAUTHORIZED_OP;
	}

	if (m_in.m11_i2 == 1) {
		//Add new uid permissions
		int ret = updateUserRights(m_in.m11_i1, m_in.m11_i3);
		print_lists();
		return ret;
	} else if (m_in.m11_i2 == 0) {
		//Add new gid permissions
		int ret = updateGroupRights(m_in.m11_i1, m_in.m11_i3);
		print_lists();
		return ret;
	}

	printf("\nERROR: Invalid id type.");
	return 1;
}

/**
 * Adds user/group to public queue blacklist list (CALLNR BLACKLISTPUBLICQ 105)
 * Incoming IPC Message format:
 *  m_in.m11_i1 = UID or GID
 *  m_in.m11_i2 = is it uid (1) or gid (0)
 */
int do_auth_perm_public() {
	register struct mproc *rmp = mp;

	if (!(isUserAdmin(rmp->mp_effuid) || isGroupAdmin(rmp->mp_effgid))) {
		printf(
				"\nERROR: Queue Authorization permissions can only be altered by admin users or groups");
		return UNAUTHORIZED_OP;
	}

	if (m_in.m11_i2 == 1) {
		//Add new uid permissions
		int ret = addPublicDeniedUser(m_in.m11_i1);
		print_lists();
		return ret;
	} else if (m_in.m11_i2 == 0) {
		//Add new gid permissions
		int ret = addPublicDeniedGroup(m_in.m11_i1);
		print_lists();
		return ret;
	}

	printf("\nERROR: Invalid id type.");
	return 1;
}

/**
 *	Creates a new queue (CALLNR OPENQ 44)
 *
 *Incoming IPC Message format:
 *  m_in.m11_i1 = Queue Type Secured (1) or Public (0)
 *  m_in.m11_i2 = Queue Capacity
 *  m_in.m11_i3 = Queue Type Blocking/Non-Blocking
 *  m_in.m11_ca1 = Queue Name
 *
 *Outgoing IPC Message format:
 *	m_in.m11_ca1 = Queue Name
 *	m_in.m11_i1 = Queue Name len
 *	(libc should check return value of this sys call and put m_in.m11_ca1 in queue handle to return it to caller)
 *
 */
int do_open_q() {

	register struct mproc *rmp = mp;

	if (m_in.m11_i1) {
		printf("\nDEBUG: Queue type is secured");
		if (!(userHasSecureAuth(rmp->mp_effuid, Q_CREATE)
				|| groupHasSecureAuth(rmp->mp_effgid, Q_CREATE))) {
			printf(
					"\nERROR: Secure Queue create permissions are denied to user with id=%d.",
					rmp->mp_effuid);
			return UNAUTHORIZED_OP;
		}
	} else if (m_in.m11_i1 == 0) {
		printf("\nDEBUG: Queue type is public");
		if (userHasDeniedPublicAuth(rmp->mp_effuid)
				|| groupHasDeniedPublicAuth(rmp->mp_effgid)) {
			printf(
					"\nERROR: Public Queue create permissions are denied to user with id=%d.",
					rmp->mp_effuid);
			return UNAUTHORIZED_OP;
		}
	} else {
		printf(
				"\nERROR: Invalid queue type, only Secured (1) or Public (0) are allowed.");
		return INVALID_Q_AUTH_TYPE;
	}

	//check if new queue can be created
	int idx = get_empty_q_slot();
	if (idx == -1) {
		printf("\nERROR: Maximum queue count of %d reached.", QIPC_MAX_Q_COUNT);
		printf("\nDEBUG: Total queues : %d", queue_count);
		debug_list();
		return QUEUE_OPEN_FAIL;
	}

	Queue *q = (Queue *) malloc(sizeof(Queue));
	q->attr = (QueueAttr *) malloc(sizeof(QueueAttr));

	q->attr->name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF,
			(vir_bytes) q->attr->name, QIPC_MAX_Q_NAME_LEN);
	q->attr->q_name_len = strlen(q->attr->name);

	if (check_queue_exist(q->attr->name) >= 0) {
		printf("\nDEBUG: Queue named %s already exists.", q->attr->name);
		debug_list();
		m_in.m11_i1 = q->attr->q_name_len;
		sys_datacopy(SELF, (vir_bytes) q->attr->name, who_e,
				(vir_bytes) m_in.m11_ca1, q->attr->q_name_len);
		free(q);
		return QUEUE_ALREADY_EXIST;
	}

	q->attr->q_auth_type = m_in.m11_i1;

	if (m_in.m11_i2 > QIPC_MAX_Q_MSG_CAP) {
		q->attr->capacity = QIPC_MAX_Q_MSG_CAP;
		printf(
				"\nWARN: Queue message capacity exceeds maximum allowed capacity of %d. Setting it to %d",
				QIPC_MAX_Q_MSG_CAP, QIPC_MAX_Q_MSG_CAP);
	} else
		q->attr->capacity = m_in.m11_i2;

	q->attr->currentcount = 0;
	q->attr->blocking = m_in.m11_i3;
	q->attr->owner_pid = rmp->mp_pid;
	q->attr->owner_uid = rmp->mp_effuid;
	q->attr->creationtime = clock_time();
	q->HEAD = NULL;
	q->TAIL = NULL;

	queue_arr[idx] = q;
	m_in.m11_i1 = q->attr->q_name_len;
	sys_datacopy(SELF, (vir_bytes) q->attr->name, who_e,
			(vir_bytes) m_in.m11_ca1, q->attr->q_name_len);

	// Create a slot for this Queue in BlockedQ List
	BlockedQ* bqnode = (BlockedQ*) malloc(sizeof(BlockedQ));
	bqnode->qname = q->attr->name;
	bqnode->blocked_rec_list_head = NULL;
	bqnode->blocked_rec_list_tail = NULL;
	blockedQ_array[idx] = bqnode;

	queue_count++;
	printf("\nINFO: Queue named %s created successfully.", q->attr->name);
	printf("\nDEBUG: Total queues : %d", queue_count);
	debug_list();
	return QUEUE_OPEN_SUCCESS;
}

/**
 *	Closes a queue (CALLNR CLOSEQ 45)
 *
 *Incoming IPC Message format:
 *  m_in.m11_ca1 = Queue Name
 *
 *Outgoing IPC Message format:
 *	<nothing>
 *	(libc should check return value of this sys call)
 *
 */
int do_close_q() {
	register struct mproc *rmp = mp;

	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	if (indx >= 0) {
		debug_list();
		Queue *q1 = queue_arr[indx];

		if (q1->attr->owner_uid != rmp->mp_effuid) {
			printf("\nDEBUG: quid=%d, iuid=%d.", q1->attr->owner_uid,
					rmp->mp_effuid);
			printf("\nERROR: Only creator user of a queue can close it.");
			return UNAUTHORIZED_OP;
		}

		q1 = NULL;
		free(q1);

		BlockedQ* bqnode = blockedQ_array[indx];
		free(bqnode);
		bqnode = NULL;

		clear_queue_entry_idx(indx);
		printf("\nINFO: Queue named %s deleted.", name);
		debug_list();
		queue_count--;
		return QUEUE_CLOSE_SUCCESS;

	}

	printf("\nWARN: Queue named %s does not exist.", name);
	debug_list();
	return QUEUE_NOT_EXIST;
}

/**
 *	Adds new message to a queue (CALLNR SENDMSGQ 69)
 *
 *Incoming IPC Message format:
 *  m_in.m11_i1 = Message receiver Count
 *  m_in.m11_i2 = Message priority
 *  m_in.m11_i3 = Message length
 *  m_in.m11_ca1 = Queue Name
 *  m_in.m11_ca2 = String data
 *
 *Outgoing IPC Message format:
 *	<nothing>
 *	(libc should check return value of this sys call)
 *
 */
int do_send_mg_q() {

	int i, pid, ret, retVal = 0;
	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	register struct mproc *rmp = mp;

	int *rID;
	int sID;
	int sNo;
	int recvCount;

	sID = rmp->mp_pid;
	printf("\nsender process ID = %d !!!!!!!!!!!!!!!!!!!!!!!!!!", sID);

	int indx = check_queue_exist(name);
	if (indx >= 0) {
		debug_list();
		Queue *q = queue_arr[indx];

		//Auth check
		if (q->attr->q_auth_type) {
			printf("\nDEBUG: Queue type is secured");
			if (!(userHasSecureAuth(rmp->mp_effuid, Q_WRITE)
					|| groupHasSecureAuth(rmp->mp_effgid, Q_WRITE))) {
				printf(
						"\nERROR: Writing to Secure Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		} else if (q->attr->q_auth_type == 0) {
			printf("\nDEBUG: Queue type is public");
			if (userHasDeniedPublicAuth(rmp->mp_effuid)
					|| groupHasDeniedPublicAuth(rmp->mp_effgid)) {
				printf(
						"\nERROR: Writing to Public Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		}

		if (q->attr->currentcount == q->attr->capacity) {
			check_sig(sID, SIGUSR2, 1);
			printf(
					"\nERROR: Queue %s has reached its maximum message capacity of %d.",
					name, q->attr->capacity);
			return MSG_ADD_QUEUE_FULL;
		}

		Qmsg *m = get_qipc_msg();

		sNo = m->senderId;
		rID = m->recieverIds;
		recvCount = m->recieverCount;

		if (q->attr->blocking == 1) {
			retVal = blocking_adder_add(sID, sNo, rID, recvCount);
		}

		if ((add_to_queue(q, m) == 0) && (retVal != -1)) {

			printf(
					"\nINFO: New message %s successfully added to queue %s. Receiver ID = %d",
					m->data, name, rID[0]);
			f_intNotifyChk(rID, recvCount);

			// wake up the receiver if he is sleeping
			// receivers will be notified on FCFS basic
			for (i = 0; i < m->recieverCount; i++) {
				pid = if_present_blocked_receiver_list(indx, m->recieverIds[i]);
				if (pid > 0) {
					printf("\n waking up receiver %d", pid);
					ret = check_sig(pid, SIGUSR1, 1);
					if (!ret) {
						printf("woke up receiver %d", pid);
						delete_from_blocked_receiver_list(indx, pid);
					}

				}
			}
			return MSG_ADD_SUCCESS;
		} else {
			check_sig(sID, SIGUSR2, 1);
			printf("\nERROR: Failed to add message to queue %s.", name);
			return MSG_ADD_FAIL;
		}
	} else {
		check_sig(sID, SIGUSR2, 1);
		printf("\nERROR: Queue named %s does not exist.", name);
		debug_list();
		return QUEUE_NOT_EXIST;
	}
}

/**
 *	Delivers message to a calling process (CALLNR RESMSGQ	70)
 *
 *Incoming IPC Message format:
 *  m_in.m11_i1 = Sender id from which message is expected
 *  m_in.m11_i2 = Should use expected sender id or not. Should be 0 or 1.
 *  m_in.m11_ca1 = Queue Name
 *
 *Outgoing IPC Message format:
 *	m_in.m11_ca2 = Message from sender, if any
 *	(libc should check return value of this sys call)
 *
 */
int do_res_mg_q() {

	register struct mproc *rmp = mp;
	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	printf("\nDEBUG: index = %d", indx);
	if (indx >= 0) {
		printf(
				"\nDEBUG: Queue %s from which message is to be received found at %d.",
				name, indx);
		debug_list();
		Queue *q = queue_arr[indx];

		//Auth check
		if (q->attr->q_auth_type) {
			printf("\nDEBUG: Queue type is secured");
			if (!(userHasSecureAuth(rmp->mp_effuid, Q_READ)
					|| groupHasSecureAuth(rmp->mp_effgid, Q_READ))) {
				printf(
						"\nERROR: Reading from Secure Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		} else if (q->attr->q_auth_type == 0) {
			printf("\nDEBUG: Queue type is public");
			if (userHasDeniedPublicAuth(rmp->mp_effuid)
					|| groupHasDeniedPublicAuth(rmp->mp_effgid)) {
				printf(
						"\nERROR: Reading from Public Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		}

		if (q->attr->currentcount == 0) {
			printf("\nINFO: No message for process in queue %s", name);
			return MSG_REC_NO_MSG;
		}

		int expected_sender = m_in.m11_i1;
		short shouldusesenderid = m_in.m11_i2;
		if (!shouldusesenderid)
			expected_sender = -1;

		register struct mproc *rmp = mp;
		pid_t receiver = rmp->mp_pid;
		int recid = m_in.m11_i3;

		printf("\nDEBUG Queue before: ");
		debug_queue(q);

		Qnode *msgnode = get_msg_from_queue(q, indx, recid, expected_sender);

		if (msgnode) {
			printf("\nDEBUG: Found message: %s", msgnode->msg->data);
			sys_datacopy(SELF, (vir_bytes) msgnode->msg->data, who_e,
					(vir_bytes) m_in.m11_ca2, msgnode->msg->dataLen);
			msgnode->msg->pendingreceiverCount--;
			if (msgnode->msg->pendingreceiverCount == 0) {
				remove_node(q, msgnode);
			}
			printf("\nDEBUG Queue after: ");
			debug_queue(q);
			return MSG_REC_SUCCESS;
		} else {
			printf("\nDEBUG Queue after: ");
			debug_queue(q);
			printf("\nINFO: Could not find message for %d ", receiver);
			return MSG_REC_NO_MSG;
		}
	} else {
		printf("\nERROR: Queue named %s does not exist.", name);
		debug_list();
		return QUEUE_NOT_EXIST;
	}
}

int do_blocking_receive() {
	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	printf("\nDEBUG: index = %d", indx);
	if (indx >= 0) {
		register struct mproc *rmp = mp;
		pid_t receiver = rmp->mp_pid;
		int rec = receiver;

		int recid = m_in.m11_i3;
		int expected_sender = m_in.m11_i1;
		short shouldusesenderid = m_in.m11_i2;
		if (!shouldusesenderid)
			expected_sender = -1;

		printf(
				"\nDEBUG: Queue %s from which message is to be received found at %d.",
				name, indx);
		debug_list();
		Queue *q = queue_arr[indx];

		//Auth check
		if (q->attr->q_auth_type) {
			printf("\nDEBUG: Queue type is secured");
			if (!(userHasSecureAuth(rmp->mp_effuid, Q_READ)
					|| groupHasSecureAuth(rmp->mp_effgid, Q_READ))) {
				printf(
						"\nERROR: Reading from Secure Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		} else if (q->attr->q_auth_type == 0) {
			printf("\nDEBUG: Queue type is public");
			if (userHasDeniedPublicAuth(rmp->mp_effuid)
					|| groupHasDeniedPublicAuth(rmp->mp_effgid)) {
				printf(
						"\nERROR: Reading from Public Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		}

		if (q->attr->currentcount == 0) {
			int deadlock = check_for_deadlock(indx, recid, expected_sender);
			if (deadlock) {
				return REC_DLOCKED;
			}

			printf("\nINFO: No message for process in queue %s", name);
			printf("\nGoing to sleep now");
			add_to_blocked_receiver_list(indx, rec, expected_sender,
					m_in.m11_i3);
			return MSG_REC_NO_MSG;
		}

		printf("\nDEBUG: E1 = %d", expected_sender);

		printf("\nDEBUG: %%%% Receiver id %d", receiver);

		printf("\nDEBUG Queue before: ");
		debug_queue(q);
		//int recid = m_in.m11_i3;
		Qnode *msgnode = get_msg_from_queue(q, indx, recid, expected_sender);

		if (msgnode) {
			printf("DEBUG: Found message: %s", msgnode->msg->data);
			sys_datacopy(SELF, (vir_bytes) msgnode->msg->data, who_e,
					(vir_bytes) m_in.m11_ca2, msgnode->msg->dataLen);
			msgnode->msg->pendingreceiverCount--;
			if (msgnode->msg->pendingreceiverCount == 0) {
				remove_node(q, msgnode);
			}
			printf("\nDEBUG Queue after: ");
			debug_queue(q);
			return MSG_REC_SUCCESS;
		} else {
			int deadlock = check_for_deadlock(indx, recid, expected_sender);
			if (deadlock) {
				return REC_DLOCKED;
			}
			printf("\nNo message for me in %s. Going to sleep now", name);
			add_to_blocked_receiver_list(indx, rec, expected_sender,
					m_in.m11_i3);
			return MSG_REC_NO_MSG;
		}
	} else {
		printf("\nERROR: Queue named %s does not exist.", name);
		debug_list();
		return QUEUE_NOT_EXIST;
	}

}

/**
 *	Sets attributes of a queue (CALLNR SETATTRQ	56)
 *
 *Incoming IPC Message format:
 *  m_in.m11_i2 = Queue Capacity
 *  m_in.m11_i3 = Queue Type Blocking/Non-Blocking
 *  m_in.m11_ca2 = Queue Name
 *
 *Outgoing IPC Message format:
 *  <nothing>
 *	(libc should check return value of this sys call)
 *
 */
int do_set_attr_q() {

	register struct mproc *rmp = mp;
	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	debug_list();

	if (indx >= 0) {
		Queue *q1 = queue_arr[indx];

		if (q1->attr->owner_uid != rmp->mp_effuid) {
			printf(
					"\nERROR: Only creator user of a queue can alter its attributes.");
			return UNAUTHORIZED_OP;
		}

		if (m_in.m11_i2 > QIPC_MAX_Q_MSG_CAP) {
			q1->attr->capacity = QIPC_MAX_Q_MSG_CAP;
			printf(
					"\nWARN: Queue message capacity exceeds maximum allowed capacity of %d. Setting it to %d",
					QIPC_MAX_Q_MSG_CAP, QIPC_MAX_Q_MSG_CAP);
		} else
			q1->attr->capacity = m_in.m11_i2;
		q1->attr->blocking = m_in.m11_i3;
		printf("\nINFO: Successfully updated attributes of queue %s", name);
		debug_list();
		free(name);
		name = NULL;
		return QUEUE_UPDATE_SUCCESS;
	}

	printf("\nERROR: Queue named %s does not exist.", name);
	debug_list();
	return QUEUE_NOT_EXIST;
}

/**
 *	Gets attributes of a queue (CALLNR GETATTRQ	57)
 *
 *Incoming IPC Message format:
 *  m_in.m11_ca2 = Queue Name
 *
 *Outgoing IPC Message format:
 *  mp_reply.m2_i1 = Current Queue Capacity
 *  mp_reply.m2_i2 = Curent Queue Type Blocking/Non-Blocking
 *
 *	(libc should check return value of this sys call)
 *
 */
int do_get_attr_q() {

	register struct mproc *rmp = mp;
	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes) m_in.m11_ca1, SELF, (vir_bytes) name,
	QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	debug_list();

	if (indx >= 0) {
		Queue *q1 = queue_arr[indx];

		//Auth check
		if (q1->attr->q_auth_type) {
			printf("\nDEBUG: Queue type is secured");
			if (!(userHasSecureAuth(rmp->mp_effuid, Q_READ)
					|| groupHasSecureAuth(rmp->mp_effgid, Q_READ))) {
				printf(
						"\nERROR: Reading from Secure Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		} else if (q1->attr->q_auth_type == 0) {
			printf("\nDEBUG: Queue type is public");
			if (userHasDeniedPublicAuth(rmp->mp_effuid)
					|| groupHasDeniedPublicAuth(rmp->mp_effgid)) {
				printf(
						"\nERROR: Reading from Public Queue permissions are denied to user with id=%d.",
						rmp->mp_effuid);
				return UNAUTHORIZED_OP;
			}
		}

		rmp->mp_reply.m2_i1 = q1->attr->capacity;
		rmp->mp_reply.m2_i2 = q1->attr->blocking;
		free(name);
		name = NULL;
		return QUEUE_UPDATE_SUCCESS;
	}

	printf("\nERROR: Queue named %s does not exist.", name);
	free(name);
	name = NULL;
	return QUEUE_NOT_EXIST;
}
