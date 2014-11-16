#include "pm.h"
#include "mproc.h"
#include <stdio.h>

void print_lists() {
	int i;
	gAuthEntity *gList;
	uAuthEntity *uList;

	printf("\n\nGroup List ");
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		gList = secure_q_gAuth_list[i];
		if (gList) {
			printf("\nGroup id = %d", gList->gid);
			printf("\nGroup mode = %d", gList->auth);
		}
	}

	printf("\n\nUser List ");
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		uList = secure_q_uAuth_list[i];
		if (uList) {
			printf("\nUser id = %d", uList->uid);
			printf("\nUser mode = %d", uList->auth);
		}
	}

	printf("\n\nExcluded group list");
	for (i = 0; i < MAX_AUTH_ENTITIES; i++)
		if (denied_public_q_gauth[i] != -1)
			printf("\nGroup id : %d", denied_public_q_gauth[i]);

	printf("\n\nExcluded user list");
	for (i = 0; i < MAX_AUTH_ENTITIES; i++)
		if (denied_public_q_uauth[i] != -1)
			printf("\nUser id : %d", denied_public_q_uauth[i]);

	printf("\n\n");
}

int addPublicDeniedGroup(gid_t gid) {

	int i, emptySlot = -1;
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (denied_public_q_gauth[i] == gid) {
			printf("\nWARN: Group already exists in public queue blacklist.");
			return 0;
		} else if (emptySlot == -1 && (denied_public_q_gauth[i] == -1)) {
			emptySlot = i;
		}
	}

	if (i == MAX_AUTH_ENTITIES && emptySlot == -1) {
		printf(
				"\nERROR: Cannot add group to public queue blacklist, max capacity reached.");
		return 1;
	}

	denied_public_q_gauth[emptySlot] = gid;
	return 0;
}

int addPublicDeniedUser(uid_t uid) {
	int i, emptySlot = -1;
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (denied_public_q_uauth[i] == uid) {
			printf("\nWARN: User already exists in public queue blacklist.");
			return 0;
		} else if (emptySlot == -1 && (denied_public_q_uauth[i] == -1)) {
			emptySlot = i;
		}
	}

	if (i == MAX_AUTH_ENTITIES && emptySlot == -1) {
		printf(
				"\nERROR: Cannot add user to public queue blacklist, max capacity reached.");
		return 1;
	}

	denied_public_q_uauth[emptySlot] = uid;
	return 0;
}

int updateGroupRights(gid_t gid, int mode) {
	gAuthEntity *gList = NULL;
	int i, emptySlot = -1;
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (secure_q_gAuth_list[i]) {
			gList = secure_q_gAuth_list[i];
			if (gList->gid == gid) {
				gList->auth = mode;
				return 0;
			}
		} else if (emptySlot == -1) {
			emptySlot = i;
		}
	}

	if (i == MAX_AUTH_ENTITIES && emptySlot == -1) {
		printf(
				"\nERROR: Cannot add new permissions for a group, max capacity reached.");
		return 1;
	}

	gAuthEntity* temp;
	temp = (gAuthEntity*) malloc(sizeof(gAuthEntity));
	temp->gid = gid;
	temp->auth = mode;
	secure_q_gAuth_list[emptySlot] = temp;

	return 0;
}

int updateUserRights(uid_t uid, int mode) {
	uAuthEntity *uList = NULL;
	int i, emptySlot = -1;
	for (i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (secure_q_uAuth_list[i]) {
			uList = secure_q_uAuth_list[i];
			if (uList->uid == uid) {
				uList->auth = mode;
				return 0;
			}
		} else if (emptySlot == -1) {
			emptySlot = i;
		}
	}

	if (i == MAX_AUTH_ENTITIES && emptySlot == -1) {
		printf(
				"\nERROR: Cannot add new permissions for an user, max capacity reached.");
		return 1;
	}

	uAuthEntity* temp;
	temp = (uAuthEntity*) malloc(sizeof(uAuthEntity));
	temp->uid = uid;
	temp->auth = mode;
	secure_q_uAuth_list[emptySlot] = temp;

	return 0;
}

short groupHasSecureAuth(gid_t gid, int auth) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		gAuthEntity* tmp = secure_q_gAuth_list[i];
		if (tmp) {
			if (tmp->gid == gid && (tmp->auth & auth))
				return 1;
		}
	}
	return 0;
}

short userHasSecureAuth(uid_t uid, int auth) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		uAuthEntity* tmp = secure_q_uAuth_list[i];
		if (tmp) {
			if (tmp->uid == uid && (tmp->auth & auth))
				return 1;
		}
	}
	return 0;
}

short groupHasDeniedPublicAuth(gid_t gid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (denied_public_q_gauth[i] == gid)
			return 1;
	}
	return 0;
}

short userHasDeniedPublicAuth(uid_t uid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (denied_public_q_uauth[i] == uid)
			return 1;
	}
	return 0;
}

short addNewAdminGroup(gid_t gid) {
	int emptySlot = -1;
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminGroups[i] == -1) {
			emptySlot = i;
		}
		if (authorizedAdminGroups[i] == gid) {
			printf("\nERROR: Admin group %d already exists.", gid);
			return 1;
		}
	}

	if (emptySlot != -1) {
		authorizedAdminGroups[emptySlot] = gid;

		for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
			if (authorizedAdminGroups[i] != -1) {
				printf("\nDEBUG: Admin group = %d", authorizedAdminGroups[i]);
			}
		}

		return 0;
	}

	printf("\nERROR: Cannot add new admin group %d, max count reached.", gid);
	return 1;
}

short addNewAdminUser(uid_t uid) {
	int emptySlot = -1;
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminUsers[i] == -1) {
			emptySlot = i;
		}
		if (authorizedAdminUsers[i] == uid) {
			printf("\nERROR: Admin user %d already exists.", uid);
			return 1;
		}

	}

	if (emptySlot != -1) {
		authorizedAdminUsers[emptySlot] = uid;
		for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
			if (authorizedAdminUsers[i] != -1) {
				printf("\nDEBUG: Admin user = %d", authorizedAdminUsers[i]);
			}
		}
		return 0;
	}

	printf("\nERROR: Cannot add new admin user %d, max count reached.", uid);
	return 1;
}

short deleteAdminGroup(gid_t gid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminGroups[i] == gid) {
			authorizedAdminGroups[i] = -1;
			return 0;
		}
	}
	printf("\nERROR: Could not find admin group with id %d.", gid);
	return 1;
}

short deleteAdminUser(uid_t uid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminUsers[i] == uid) {
			authorizedAdminUsers[i] = -1;
			return 0;
		}
	}
	printf("\nERROR: Could not find admin user with id %d.", uid);
	return 1;
}

short isUserAdmin(uid_t uid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminUsers[i] == uid) {
			return 1;
		}
	}
	return 0;
}

short isGroupAdmin(gid_t gid) {
	for (int i = 0; i < MAX_AUTH_ENTITIES; i++) {
		if (authorizedAdminGroups[i] == gid) {
			return 1;
		}
	}
	return 0;
}

/**
 * Adds node to tail of a queue
 */
int add_to_queue(Queue *q, Qmsg *m) {

	Qnode * mnode = (Qnode *) malloc(sizeof(Qnode));
	if (mnode == NULL) {
		printf("\nERROR: Failed to allocate memory for message node.");
		return -1;
	}

	mnode->next = NULL;
	mnode->msg = m;

	if (q->HEAD == NULL) {
		mnode->prev = NULL;
		q->HEAD = mnode;
		q->TAIL = mnode;
	} else {
		mnode->prev = q->TAIL;
		q->TAIL->next = mnode;
		q->TAIL = mnode;
	}

	q->attr->currentcount++;

	debug_queue(q);

	printf("\nDEBUG: Total number of message is queue %s are %d ",
			q->attr->name, q->attr->currentcount);
	return 0;
}

Qnode *get_msg_from_queue(Queue *q, int indx, pid_t receiver,
		pid_t expected_sender) {

	Qnode *tmp = q->HEAD;
	Qnode *tmsg = NULL;
	int i, pid, rmv_yes;
	int sNo;

	while (tmp) {
		//Check for expired messages, remove them from queue
		if (tmp->msg->expiryts < clock_time()) {
			printf("\nINFO: Deleting expired message: %s", tmp->msg->data);
			Qnode *expiredmsg = tmp;
			Qmsg* tmp1 = tmp->msg;
			// remove its receipients from blocked queue
			for (i = 0; i < tmp1->recieverCount; i++) {
				pid = if_present_blocked_receiver_list(indx,
						tmp1->recieverIds[i]);
				if (pid > 0) {
					delete_from_blocked_receiver_list(indx, pid);
				}
			}
			tmp = tmp->next;
			remove_node(q, expiredmsg);
		} else {
			pid_t current_sender = tmp->msg->senderId;
			//Check if a specific sender id is required by receiver
			if (expected_sender != -1)
				current_sender = expected_sender;

			sNo = current_sender;
			rmv_yes = 1;
			if (current_sender == tmp->msg->senderId) {
				for (int i = 0; i < tmp->msg->recieverCount; i++) {
					if (tmp->msg->recieverIds[i] == receiver) {
						if (tmsg == NULL
								|| (tmsg->msg->priority > tmp->msg->priority)) {
							tmsg = tmp;
						}
						break;
					}
				}
			}
			tmp = tmp->next;
		}
	}

	if (rmv_yes == 1) {
		remove_send_blocking_rid(sNo);
	}
	return tmsg;
}

void remove_node(Queue *q, Qnode *delnode) {
	if (delnode) {
		/* If node to be deleted is head node */
		if (delnode == q->HEAD) {
			q->HEAD = delnode->next;
		}
		/* If node to be deleted is tail node */
		if (delnode == q->TAIL) {
			q->TAIL = delnode->prev;
		}
		/* Change next only if node to be deleted is NOT the last node */
		if (delnode->next != NULL)
			delnode->next->prev = delnode->prev;
		/* Change prev only if node to be deleted is NOT the first node */
		if (delnode->prev != NULL)
			delnode->prev->next = delnode->next;
		free(delnode);
		delnode = NULL;
		q->attr->currentcount--;
	}
}

/**
 *  Get a queue with specific name
 */
Queue * get_queue(char *queue_name) {
	int i = check_queue_exist(queue_name);
	if (i != -1)
		return queue_arr[i];
	return NULL;
}

void debug_list() {
	printf("\n");
	int i;
	for (i = 0; i < QIPC_MAX_Q_COUNT; i++) {
		if (queue_arr[i] != NULL) {
			printf("\n%d.Name=%s; Type=%d; Cap=%d : ", i,
					queue_arr[i]->attr->name, queue_arr[i]->attr->blocking,
					queue_arr[i]->attr->capacity);
		}
	}
	printf("\n");
}

void debug_queue(Queue *q) {
	Qnode *tmp1 = q->HEAD;
	printf("\nDEBUG:");
	if (tmp1 != NULL) {
		printf(" Data = %s", tmp1->msg->data);
		while (tmp1->next != NULL) {
			tmp1 = tmp1->next;
			printf(" Data = %s", tmp1->msg->data);
		}
	} else
		printf("\nDEBUG: tmp is NULL ");
}
/**
 *  Check if a queue exists
 */
int get_empty_q_slot() {
	int i;
	for (i = 0; i < QIPC_MAX_Q_COUNT; i++) {
		if (queue_arr[i] == NULL)
			return i;
	}
	return -1;
}

/**
 *  Check if a queue exists. If yes, return its index.
 */
int check_queue_exist(char *queue_name) {
	int i;
	for (i = 0; i < QIPC_MAX_Q_COUNT; i++) {
		if (queue_arr[i] != NULL) {
			if (!strcmp(queue_arr[i]->attr->name, queue_name)) {
				return i;
			}
		}
	}
	return -1;
}

int clear_queue_entry(char *queue_name) {
	int idx = check_queue_exist(queue_name);
	if (idx >= 0) {
		clear_queue_entry_idx(idx);
		return 0;
	}
	return 1;
}

void clear_queue_entry_idx(int index) {
	queue_arr[index] = NULL;
	blockedQ_array[index] = NULL;
}

/**
 * Convert Incoming IPC Message into incoming QPIC specific queue message
 *
 */
Qmsg * get_qipc_msg() {
	Qmsg *tmp = (Qmsg *) malloc(sizeof(Qmsg));
	if (tmp != NULL) {
		//tmp->dataLen = cap_msg_len(m_in.m11_i3);
		tmp->data = (char *) malloc(MAX_DATA_LEN);
		sys_datacopy(who_e, (vir_bytes) m_in.m11_ca2, SELF,
				(vir_bytes) tmp->data, MAX_DATA_LEN);
		tmp->dataLen = strlen(tmp->data);
		//tmp->senderId = rmp->mp_pid;
		tmp->senderId = m_in.m11_i3;
		printf("\nDEBUG: Sender = %d", tmp->senderId);
		tmp->expiryts = m_in.m11_t1;
		printf("\nDEBUG: Expiry ts = %d", tmp->expiryts);
		tmp->priority = m_in.m11_i2;
		printf("\nDEBUG: Priority = %d", tmp->priority);
		tmp->rests = clock_time();
		tmp->recieverCount = m_in.m11_i1;
		tmp->pendingreceiverCount = tmp->recieverCount;
		tmp->recieverIds = (int *) malloc(tmp->recieverCount * sizeof(int));
		sys_datacopy(who_e, (vir_bytes) m_in.m11_e1, SELF,
				(vir_bytes) tmp->recieverIds, tmp->recieverCount * sizeof(int));

		int ii;
		for (ii = 0; ii < tmp->recieverCount; ii++) {
			printf("\nDEBUG: Rec %d = %d", ii, tmp->recieverIds[ii]);
		}
	}
	return tmp;
}

/**
 *  Avoid buffer overrun
 */
int cap_msg_len(int len) {
	if (len > QIPC_MAX_MSG_LEN) {
		printf(
				"\nWARN: Message length is more than %d, message will be truncated.",
				QIPC_MAX_MSG_LEN);
		return QIPC_MAX_MSG_LEN;
	}
	return len;
}

/**
 * Get system's current time
 */
time_t clock_time() {
	register int k;
	clock_t uptime;
	time_t boottime;

	if ((k = getuptime2(&uptime, &boottime)) != OK)
		panic("clock_time: getuptme2 failed: %d", k);

	return ((time_t) (boottime + (uptime / sys_hz())));
}

void add_to_blocked_receiver_list(int indx, int pid, int sendid, int recid) {
	BlockedQ* bqnode = blockedQ_array[indx];

	if (bqnode->blocked_rec_list_head == NULL) {

		bqnode->blocked_rec_list_head = (ProcNode *) malloc(sizeof(ProcNode));
		bqnode->blocked_rec_list_head->pid = pid;
		bqnode->blocked_rec_list_head->sendid = sendid;
		bqnode->blocked_rec_list_head->recid = recid;
		bqnode->blocked_rec_list_head->prev = NULL;
		bqnode->blocked_rec_list_head->next = NULL;

		bqnode->blocked_rec_list_tail = bqnode->blocked_rec_list_head;
		printf("\nReceiver %d %d added to blocked Queue for sender %d", recid,
				pid, sendid);
	} else {

		ProcNode *temp;
		temp = (ProcNode *) malloc(sizeof(ProcNode));
		temp->pid = pid;
		temp->sendid = sendid;
		temp->recid = recid;
		temp->prev = temp->next = NULL;

		bqnode->blocked_rec_list_tail->next = temp;
		temp->prev = bqnode->blocked_rec_list_tail;

		bqnode->blocked_rec_list_tail = bqnode->blocked_rec_list_tail->next;
		printf("\nReceiver %d %d added to blocked Queue for sender %d", recid,
				pid, sendid);

	}
}

void delete_from_blocked_receiver_list(int indx, int pid) {
	BlockedQ* bqnode = blockedQ_array[indx];

	if (bqnode->blocked_rec_list_head == NULL)
		return;

	ProcNode *temp = bqnode->blocked_rec_list_head;
	ProcNode *prev;
	int found = 0;

	while (temp != NULL) {
		if (temp->pid == pid) {
			found = 1;
			break;
		}
		prev = temp;
		temp = temp->next;
	}

	if (found) {
		if (temp == bqnode->blocked_rec_list_head) {
			if (temp->next) {
				prev = temp;
				temp = temp->next;
				temp->prev = NULL;
				bqnode->blocked_rec_list_head = temp;
				free(prev);
			} else {
				free(bqnode->blocked_rec_list_head);
				bqnode->blocked_rec_list_head = NULL;
			}

			printf("\nReceiver %d removed from blocked Queue", pid);

		} else if (temp == bqnode->blocked_rec_list_tail) {
			prev = temp;
			temp = temp->prev;
			temp->next = NULL;
			free(prev);
			bqnode->blocked_rec_list_tail = temp;
		} else {
			prev->next = temp->next;
			(temp->next)->prev = prev;
			free(temp);
		}
	}
}

int if_present_blocked_receiver_list(int indx, int recid) {
	BlockedQ* bqnode = blockedQ_array[indx];

	ProcNode *temp = bqnode->blocked_rec_list_head;

	while (temp != NULL) {

		if (temp->recid == recid) {
			printf("\nReceiver %d found in blocked queue", recid);
			return temp->pid;
		}
		temp = temp->next;
	}

	return -1;

}

int check_for_deadlock(int indx, int recid, int sendid) {
	BlockedQ* bqnode = blockedQ_array[indx];

	ProcNode *temp = bqnode->blocked_rec_list_head;

	while (temp != NULL) {
		if (temp->recid == sendid && temp->sendid == recid) {
			printf("\nDeadlock");
			return 1;
		}
		temp = temp->next;
	}

	return 0;
}

int f_intNotifyChk(pid_t *rID, int recvCount) {
	int l_intNotifierCntIter;
	int retVal;
	int iter;
	printf("\nCount = %d", recvCount);

	iter = 0;
	while (iter < recvCount) {
		for (l_intNotifierCntIter = 0; l_intNotifierCntIter < notifier_count;
				l_intNotifierCntIter++) {
			printf("rID = %d", rID[iter]);
			if (rID[iter] == g_arrNotificationPID[l_intNotifierCntIter][1]) {
				printf("\n Notification sent for pid = %d\n",
						g_arrNotificationPID[l_intNotifierCntIter][0]);
				retVal = check_sig(
						g_arrNotificationPID[l_intNotifierCntIter][0], 10, 1);
			}
		}
		iter++;
	}
	return retVal;
}

int blocking_adder_add(pid_t sID, int sNo, int *rID, int recvCount) {
	int sndriter;
	int retVal = 0;
	int iter;

	iter = 0;
	while (iter < recvCount) {
		if (rID[iter] == sNo) {
			printf("\nError : Sender trying to send to itself %d", sID);
			check_sig(sID, SIGUSR2, 1);
			return -1;
		} else if (recvCount < 1) {
			printf("\nError : No Receivers; Ending blocked send %d", sID);
			check_sig(sID, SIGUSR2, 1);
			return -1;
		}

		else {
			for (sndriter = 0; sndriter < block_sender_cnt; sndriter++) {
				if (rID[iter] == blocking_sender[sndriter][2]) {
					printf("\n Error: Recevier %d doing blocking send",
							blocking_sender[sndriter][0]);
					check_sig(sID, SIGUSR2, 1);
					retVal = -1;
					return retVal;
				}
			}
		}
		iter++;
	}

	blocking_sender[block_sender_cnt][0] = sID;
	blocking_sender[block_sender_cnt][1] = recvCount;
	blocking_sender[block_sender_cnt][2] = sNo;
	block_sender_cnt++;
	printf("\n blocking process %d added with %d receivers", sID, recvCount);
	return retVal;
}

int remove_send_blocking_rid(int sNo) {
	int iter;
	int iter2;
	pid_t sID;

	for (iter = 0; iter < block_sender_cnt; iter++) {
		if (sNo == blocking_sender[iter][2]) {
			blocking_sender[iter][1] = blocking_sender[iter][1] - 1;
			sID = blocking_sender[iter][0];
			if (blocking_sender[iter][1] == 0) {
				for (iter2 = iter; iter2 < block_sender_cnt; iter2++) {
					blocking_sender[iter2][0] = blocking_sender[iter2 + 1][0];
					blocking_sender[iter2][1] = blocking_sender[iter2 + 1][1];
					blocking_sender[iter2][2] = blocking_sender[iter2 + 1][2];
				}
				block_sender_cnt--;
				printf("\nItems left is %d", block_sender_cnt);
				printf("\nProcess %d blocking send finished,  No %d", sID, sNo);
				check_sig(sID, SIGUSR1, 1);
			}
			return 1;
		}
	}

	return 0;
}
