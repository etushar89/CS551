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

EXTERN char* qipc_msg[2];
EXTERN Queue* queue_arr[QIPC_MAX_Q_COUNT];	//holds array of pointers to all queues present
EXTERN int queue_count;	//count of current queues present

time_t clock_time();
Qmsg * get_qipc_msg();
int cap_msg_len();
int get_empty_q_slot();
int check_queue_exist(char *);
Queue * get_queue(char *);
int add_to_queue(Queue *, Qmsg *);
Qnode *get_msg_from_queue(Queue *, endpoint_t, endpoint_t);
int clear_queue_entry(char *);
void clear_queue_entry_idx(int);
void remove_node(Queue *, Qnode *);

void debug_list();
void debug_queue(Queue *);

//stdlib funcs
void free(void *ptr);
void *malloc(size_t size);
int strcmp(const char *s1, const char *s2);
char *strcpy(char *to, const char *from);
size_t strlen(const char *str);

#endif /* QIPC_H_ */
