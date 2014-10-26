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
 *	Creates a new queue (CALLNR OPENQ 44)
 *
 *Incoming IPC Message format:
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

	//check if new queue can be created
	int idx = get_empty_q_slot();
	if(idx==-1) {
		printf("\nERROR: Maximum queue count of %d reached.", QIPC_MAX_Q_COUNT);
		printf("\nDEBUG: Total queues : %d", queue_count);
		debug_list();
		return QUEUE_OPEN_FAIL;
	}

	Queue *q = (Queue *) malloc(sizeof(Queue));
	q->attr = (QueueAttr *) malloc(sizeof(QueueAttr));

	q->attr->name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) q->attr->name, QIPC_MAX_Q_NAME_LEN);
	q->attr->q_name_len = strlen(q->attr->name);

	if(check_queue_exist(q->attr->name)>=0) {
		printf("\nERROR: Queue named %s already exists.", q->attr->name);
		debug_list();
		free(q);
		return QUEUE_ALREADY_EXIST;
	}

	if(m_in.m11_i2 > QIPC_MAX_Q_MSG_CAP) {
		q->attr->capacity = QIPC_MAX_Q_MSG_CAP;
		printf("\nWARN: Queue message capacity exceeds maximum allowed capacity of %d. Setting it to %d", QIPC_MAX_Q_MSG_CAP, QIPC_MAX_Q_MSG_CAP);
	} else
		q->attr->capacity = m_in.m11_i2;

	q->attr->currentcount = 0;
	q->attr->blocking = m_in.m11_i3;
	q->attr->owner = rmp->mp_pid;
	q->attr->creationtime = clock_time();
	q->HEAD = NULL;
	q->TAIL = NULL;

	queue_arr[idx] = q;
	m_in.m11_i1 = q->attr->q_name_len;
	sys_datacopy(SELF, (vir_bytes)  q->attr->name, who_e,(vir_bytes) m_in.m11_ca1, q->attr->q_name_len);
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

	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) name, QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	if(indx>=0) {
		debug_list();
		Queue *q1=queue_arr[indx];
		//endpoint_t qowner = q1->attr->owner;
		//if(qowner == who_e) {
		q1 = NULL;
		free(q1);
		clear_queue_entry_idx(indx);
		printf("\nINFO: Queue named %s deleted.", name);
		debug_list();
		queue_count--;
		return QUEUE_CLOSE_SUCCESS;
		//} else {
			//printf("\nERROR: Only queue owner %d can close this queue.", qowner);
		//}
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

	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) name, QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	if(indx>=0) {
		debug_list();
		Queue *q = queue_arr[indx];
		if(q->attr->currentcount==q->attr->capacity) {
			printf("\nERROR: Queue %s has reached its maximum message capacity of %d.", name, q->attr->capacity);
			return MSG_ADD_QUEUE_FULL;
		}
		Qmsg *m = get_qipc_msg();
		if(add_to_queue(q, m)==0) {
			printf("\nINFO: New message %s successfully added to queue %s.", m->data, name);
			return MSG_ADD_SUCCESS;
		} else {
			printf("\nERROR: Failed to add message to queue %s.", name);
			return MSG_ADD_FAIL;
		}
	} else {
		printf("\nERROR: Queue named %s does not exist.", name);
		debug_list();
		return QUEUE_NOT_EXIST;
	}
}

/**
 * Adds node to tail of a queue
 */
int add_to_queue(Queue *q, Qmsg *m) {

	Qnode * mnode = (Qnode *) malloc(sizeof(Qnode));
	if(mnode == NULL) {
		printf("\nERROR: Failed to allocate memory for message node.");
		return -1;
	}

	mnode->next = NULL;
	mnode->msg = m;

	if(q->HEAD == NULL) {
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

	printf("\nDEBUG: Total number of message is queue %s are %d ",q->attr->name,q->attr->currentcount);
	return 0;
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

	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) name, QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	printf("\nDEBUG: index = %d", indx);
	if(indx>=0) {
		printf("\nDEBUG: Queue %s from which message is to be received found at %d.", name, indx);
		debug_list();
		Queue *q = queue_arr[indx];
		if(q->attr->currentcount==0) {
			printf("\nINFO: No message for process in queue %s", name);
			return MSG_REC_NO_MSG;
		}

		pid_t expected_sender = m_in.m11_i1;
		short shouldusesenderid = m_in.m11_i2;
		if(!shouldusesenderid)
			expected_sender = -1;

		printf("\nDEBUG: E1 = %d", expected_sender);
		register struct mproc *rmp = mp;
		pid_t receiver = rmp->mp_pid;
		printf("\nDEBUG: %%%% Receiver id %d", receiver);

		printf("\nDEBUG Queue before: ");
		debug_queue(q);

		Qnode *msgnode = get_msg_from_queue(q, receiver, expected_sender);

		if(msgnode) {
			printf("DEBUG: Found message: %s", msgnode->msg->data);
			sys_datacopy(SELF, (vir_bytes)  msgnode->msg->data, who_e,(vir_bytes) m_in.m11_ca2, msgnode->msg->dataLen);
			msgnode->msg->pendingreceiverCount--;
			if(msgnode->msg->pendingreceiverCount==0) {
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

Qnode *get_msg_from_queue(Queue *q, pid_t receiver, pid_t expected_sender) {

	Qnode *tmp = q->HEAD;
	Qnode *tmsg = NULL;

	while(tmp) {
		//Check for expired messages, remove them from queue
		if(tmp->msg->expiryts < clock_time()) {
			printf("\nINFO: Deleting expired message: %s", tmp->msg->data);
			Qnode *expiredmsg = tmp;
			tmp = tmp->next;
			remove_node(q, expiredmsg);
		} else {
			pid_t current_sender = tmp->msg->senderId;
			//Check if a specific sender id is required by receiver
			if(expected_sender!=-1)
				current_sender = expected_sender;

			printf("\nDEBUG: E = %d == %d", current_sender, tmp->msg->senderId);
			if(current_sender == tmp->msg->senderId) {
				for(int i=0; i < tmp->msg->recieverCount; i++) {
					printf("\nDEBUG: %d == %d", tmp->msg->recieverIds[i], receiver);
					if(tmp->msg->recieverIds[i] == receiver) {
						if(tmsg==NULL || (tmsg->msg->priority > tmp->msg->priority)) {
							tmsg = tmp;
						}
						break;
					}
				}
			}
			tmp = tmp->next;
		}
	}

	return tmsg;
}

void remove_node(Queue *q, Qnode *delnode) {
	if(delnode) {
		/* If node to be deleted is head node */
		if(delnode==q->HEAD) {
			q->HEAD = delnode->next;
		}
		/* If node to be deleted is tail node */
		if(delnode==q->TAIL) {
			q->TAIL = delnode->prev;
		}
		/* Change next only if node to be deleted is NOT the last node */
		if(delnode->next != NULL)
			delnode->next->prev = delnode->prev;
		/* Change prev only if node to be deleted is NOT the first node */
		if(delnode->prev != NULL)
			delnode->prev->next = delnode->next;
		free(delnode);
		delnode = NULL;
		q->attr->currentcount--;
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

	char *name = (char *) malloc(QIPC_MAX_Q_NAME_LEN);
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) name, QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	debug_list();

	if(indx>=0) {
		Queue *q1=queue_arr[indx];
		if(m_in.m11_i2 > QIPC_MAX_Q_MSG_CAP) {
			q1->attr->capacity = QIPC_MAX_Q_MSG_CAP;
			printf("\nWARN: Queue message capacity exceeds maximum allowed capacity of %d. Setting it to %d", QIPC_MAX_Q_MSG_CAP, QIPC_MAX_Q_MSG_CAP);
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
	sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) name, QIPC_MAX_Q_NAME_LEN);

	int indx = check_queue_exist(name);
	debug_list();

	if(indx>=0) {
		Queue *q1 = queue_arr[indx];
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

/**
 *  Get a queue with specific name
 */
Queue * get_queue(char *queue_name) {
	int i = check_queue_exist(queue_name);
	if(i!=-1)
		return queue_arr[i];
	return NULL;
}

void debug_list() {
	printf("\n");
	int i;
	for(i=0;i<QIPC_MAX_Q_COUNT;i++) {
		  if(queue_arr[i]!=NULL) {
			  printf("\n%d.Name=%s; Type=%d; Cap=%d : ", i, queue_arr[i]->attr->name,queue_arr[i]->attr->blocking,queue_arr[i]->attr->capacity);
		  }
	}
	printf("\n");
}

void debug_queue(Queue *q) {
	Qnode *tmp1 = q->HEAD;
	printf("\nDEBUG:");
	if(tmp1!=NULL) {
		printf(" Data = %s",tmp1->msg->data);
		while(tmp1->next != NULL) {
			tmp1 = tmp1->next;
			printf(" Data = %s",tmp1->msg->data);
		}
	} else
		printf("\nDEBUG: tmp is NULL ");
}
/**
 *  Check if a queue exists
 */
int get_empty_q_slot() {
	int i;
	for(i=0;i<QIPC_MAX_Q_COUNT;i++) {
		  if(queue_arr[i]==NULL)
			  return i;
	}
	return -1;
}

/**
 *  Check if a queue exists. If yes, return its index.
 */
int check_queue_exist(char *queue_name) {
	int i;
	for(i=0;i<QIPC_MAX_Q_COUNT;i++) {
		  if(queue_arr[i]!=NULL) {
			  if(!strcmp(queue_arr[i]->attr->name, queue_name)) {
				  return i;
			  }
		  }
	}
	return -1;
}

int clear_queue_entry(char *queue_name) {
	int idx = check_queue_exist(queue_name);
	if(idx>=0) {
		clear_queue_entry_idx(idx);
		return 0;
	}
	return 1;
}

void clear_queue_entry_idx(int index) {
	queue_arr[index] = NULL;
}

/**
 * Convert Incoming IPC Message into incoming QPIC specific queue message
 *
 */
Qmsg * get_qipc_msg() {
	register struct mproc *rmp = mp;
	Qmsg *tmp = (Qmsg *) malloc(sizeof(Qmsg));
	if(tmp!=NULL) {
		tmp->dataLen = cap_msg_len(m_in.m11_i3);
		tmp->data = (char *) malloc(tmp->dataLen);
		sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca2, SELF,(vir_bytes) tmp->data, tmp->dataLen);
		tmp->senderId = rmp->mp_pid;
		printf("\nDEBUG: Sender = %d", tmp->senderId);
		tmp->expiryts = m_in.m11_t1;
		printf("\nDEBUG: Expiry ts = %d", tmp->expiryts);
		tmp->priority = m_in.m11_i2;
		printf("\nDEBUG: Priority = %d", tmp->priority);
		tmp->rests = clock_time();
		tmp->recieverCount = m_in.m11_i1;
		tmp->pendingreceiverCount = tmp->recieverCount;
		tmp->recieverIds = (int *) malloc(tmp->recieverCount * sizeof(int));
		sys_datacopy(who_e, (vir_bytes)  m_in.m11_e1, SELF,(vir_bytes) tmp->recieverIds, tmp->recieverCount * sizeof(int));

		int ii;
		for(ii=0; ii<tmp->recieverCount; ii++) {
			printf("\nDEBUG: Rec %d = %d",ii, tmp->recieverIds[ii]);
		}
	}
	return tmp;
}

/**
 *  Avoid buffer overrun
 */
int cap_msg_len(int len) {
	if(len > QIPC_MAX_MSG_LEN) {
		printf("\nWARN: Message length is more than %d, message will be truncated.", QIPC_MAX_MSG_LEN);
		return QIPC_MAX_MSG_LEN;
	}
	return len;
}

/**
 * Get system's current time
 */
time_t clock_time()
{
  register int k;
  clock_t uptime;
  time_t boottime;

  if ( (k=getuptime2(&uptime, &boottime)) != OK)
		panic("clock_time: getuptme2 failed: %d", k);

  return( (time_t) (boottime + (uptime/sys_hz())));
}
