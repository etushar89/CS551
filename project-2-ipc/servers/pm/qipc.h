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
#define MAX_BLOCKING_SEND 16

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
#define UNAUTHORIZED_OP	14
#define INVALID_Q_AUTH_TYPE	15

#define SECURE_Q	1
#define PUBLIC_Q	0

typedef struct qipc_qattr {
	int capacity;         // maximum message capacity of the queue
	int currentcount;         // number of messages present in queue
	int blocking;	//queue type, blocking or non-blocking	//TODO Remove this
	int q_name_len;	//queue name length
	short q_auth_type;	//secured (1) or public (0)
	char* name;	//name of the queue
	pid_t owner_pid;	//the process id of the owner
	uid_t owner_uid;	//the process id of the owner
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
	int recieverCount;// total number f processes which are expected to consume this message
	int pendingreceiverCount;// how many processes are yet to consume the message
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
} Queue;

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
} BlockedQ;

//Authorization modes
#define Q_READ	00100
#define Q_WRITE	00200
#define Q_CREATE	00400
#define Q_DROP	01000

#define MAX_AUTH_ENTITIES	8

typedef struct gAuthEntity {
	int auth;
	gid_t gid;
} gAuthEntity;

typedef struct uAuthEntity {
	int auth;
	uid_t uid;
} uAuthEntity;

//Holds list of groups who can alter queue permissions
EXTERN gid_t authorizedAdminGroups[MAX_AUTH_ENTITIES];
//Holds list of users who can alter queue permissions
EXTERN uid_t authorizedAdminUsers[MAX_AUTH_ENTITIES];

//Holds group permits for secured queues
EXTERN gAuthEntity* secure_q_gAuth_list[MAX_AUTH_ENTITIES];
//Holds user permits for secured queues
EXTERN uAuthEntity* secure_q_uAuth_list[MAX_AUTH_ENTITIES];

//Holds groups which are denied access to public queue
EXTERN gid_t denied_public_q_gauth[MAX_AUTH_ENTITIES];
//Holds users which are denied access to public queue
EXTERN uid_t denied_public_q_uauth[MAX_AUTH_ENTITIES];

EXTERN Queue* queue_arr[QIPC_MAX_Q_COUNT];//holds array of pointers to all queues present
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
Qnode *get_msg_from_queue(Queue *, int, endpoint_t, endpoint_t);
int clear_queue_entry(char *);
void clear_queue_entry_idx(int);
void remove_node(Queue *, Qnode *);

void debug_list();
void debug_queue(Queue *);

int remove_send_blocking_rid(pid_t);
int f_intNotifyChk(pid_t *, int);

//Auth related
int parse_secure();
void print_lists();
int nextline(int fp);
short groupHasSecureAuth(gid_t, int);
short userHasSecureAuth(uid_t, int);
short groupHasDeniedPublicAuth(gid_t);
short userHasDeniedPublicAuth(uid_t);
short addNewAdminGroup(gid_t);
short addNewAdminUser(uid_t);
short deleteAdminGroup(gid_t);
short deleteAdminUser(uid_t);
int updateGroupRights(gid_t, int);
int updateUserRights(uid_t, int);
short isUserAdmin(uid_t);
short isGroupAdmin(uid_t);
int addPublicDeniedGroup(gid_t);
int addPublicDeniedUser(uid_t);

// Blocked Receiver List related functions
void add_to_blocked_receiver_list(int, int, int, int);
void delete_from_blocked_receiver_list(int, int);
int if_present_blocked_receiver_list(int, int);
int check_for_deadlock(int, int, int);
int blocking_adder_add(pid_t, int, int *, int);

//stdlib funcs
void free(void *);
void *malloc(size_t);
int strcmp(const char *, const char *);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
size_t strlen(const char *);
int atoi(const char *);

#endif /* QIPC_H_ */
