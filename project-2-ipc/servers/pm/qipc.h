/*
 * qipc.h
 *
 *  Created on: 24-Oct-2014
 *      Author: matrix
 */

#ifndef QIPC_H_
#define QIPC_H_

#define QIPC_MAX_MSG_LEN 8	//String message data max length
#define QIPC_MAX_Q_NAME_LEN 8	//Queue name max length
#define QIPC_MAX_Q_COUNT 4	//Maximum number of queues that can be present at a time in system
#define QIPC_MAX_Q_MSG_CAP 8	//Maximum number of messages in one queue
#define MAX_DATA_LEN      8

#define QIPC_MAX_NOTIFIER_COUNT 2 //Maximum number of processes that can request for notification
#define MAX_BLOCKING_SEND 100

#define BLOCKING	1
#define NON_BLOCKING	0
#define QIPC_DEFAULT_Q_TYPE	NON_BLOCKING

#define QUEUE_OPEN_SUCCESS	0
#define QUEUE_ALREADY_EXIST	1
#define QUEUE_OPEN_FAIL	2
#define MSG_ADD_SUCCESS	3
#define MSG_ADD_QUEUE_FULL	4
#define MSG_ADD_FAIL	5
#define MSG_REC_SUCCESS	6
#define MSG_REC_NO_MSG	7
#define MSG_REC_FAIL	8
#define QUEUE_NOT_EXIST	9
#define QUEUE_CLOSE_SUCCESS	10
#define QUEUE_UPDATE_SUCCESS	11
#define QUEUE_UPDATE_FAIL	12
#define REC_DLOCKED             13

typedef struct qipc_qattr {
	int capacity;         // maximum message capacity of the queue
	int currentcount;         // number of messages present in queue
	int blocking;	//queue type, blocking or non-blocking	//TODO Remove this
	int q_name_len;	//queue type, blocking or non-blocking
	char* name;	//name of the queue
	pid_t owner;	//the process id of the oqner
	time_t creationtime;	//message received timestamp
} QueueAttr;

typedef struct qipc_message {
	char* data;	//message payload
	pid_t senderId;	//sender of the message
	pid_t *recieverIds;	//receivers intended by this message
	int priority;	//priority of the message
	int dataLen;	//priority of the message
	time_t expiryts;	//message expiry timestamp
	time_t rests;	//message received timestamp
	int recieverCount;	// total number f processes which are expected to consume this message
	int pendingreceiverCount;	// how many processes are yet to consume the message
} Qmsg;

typedef struct QueueNode {
	Qmsg *msg;
	struct QueueNode *prev;
	struct QueueNode *next;
} Qnode;

typedef struct Queue {
	QueueAttr *attr;
	Qnode *HEAD;
	Qnode *TAIL;
} Queue ;

typedef struct ProcessNode {
        int pid;
        int recid;
        int sendid;
	struct ProcessNode *prev;
        struct ProcessNode *next;
} ProcNode;

typedef struct BlockedQ {
	char *qname;
	ProcNode *blocked_rec_list_head;
	ProcNode *blocked_rec_list_tail;
}BlockedQ;

EXTERN Queue* queue_arr[QIPC_MAX_Q_COUNT];	//holds array of pointers to all queues present
EXTERN int queue_count;	//count of current queues present

endpoint_t g_arrNotificationPID[QIPC_MAX_NOTIFIER_COUNT][2];
int notifier_count;

endpoint_t blocking_sender[MAX_BLOCKING_SEND][3];
int block_sender_cnt;

EXTERN BlockedQ* blockedQ_array[QIPC_MAX_Q_COUNT];

time_t clock_time();
Qmsg * get_qipc_msg();
int cap_msg_len();
int get_empty_q_slot();
int check_queue_exist(char *);
Queue * get_queue(char *);
int add_to_queue(Queue *, Qmsg *);
Qnode *get_msg_from_queue(Queue *, int indx, endpoint_t, endpoint_t);
int clear_queue_entry(char *);
void clear_queue_entry_idx(int);
void remove_node(Queue *, Qnode *);

void debug_list();
void debug_queue(Queue *);

int remove_send_blocking_rid(pid_t sID);
int f_intNotifyChk(pid_t *rID, int recvCount);

// Blocked Receiver List related functions
void add_to_blocked_receiver_list(int indx, int pid, int sendid, int recid);
void delete_from_blocked_receiver_list(int indx, int pid);
int if_present_blocked_receiver_list(int indx, int recid);
int check_for_deadlock(int indx, int rec, int sendid);

//stdlib funcs
void free(void *ptr);
void *malloc(size_t size);
int strcmp(const char *s1, const char *s2);
char *strcpy(char *to, const char *from);
size_t strlen(const char *str);

#endif /* QIPC_H_ */
