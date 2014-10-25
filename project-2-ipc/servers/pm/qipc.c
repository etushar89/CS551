/*
 * qipc.c
 *
 *  Created on: 24-Oct-2014
 *      Author: matrix
 */

#include "pm.h"
#include <stdio.h>

void do_sendmsg() {
	qmsg *t = get_qipc_msg();
	strcpy(qipc_msg[0],t->data);
	sys_datacopy(SELF, (vir_bytes)  t->data, SELF,(vir_bytes) qipc_msg[0], t->dataLen);
	printf("Saved message: %s\n",qipc_msg[0]);
}

void do_receive_msg() {
	sys_datacopy(SELF, (vir_bytes)  qipc_msg[0], who_e,(vir_bytes) m_in.m11_ca1, QIPC_MAX_MSG_LEN);
}

/*
void do_mq_open() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_close() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_send() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_receive() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_reqnotify() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_setaatr() {
	printf("Hello World! : %d", m_in.m_source);
}

void do_mq_getaatr() {
	printf("Hello World! : %d", m_in.m_source);
}
*/

/**
 * Convert Incoming IPC Message into incoming QPIC specific queue message
 *
 */
qmsg * get_qipc_msg() {
	qmsg *tmp = (qmsg *) malloc(sizeof(qmsg));
	if(tmp!=NULL) {
		tmp->dataLen = cap_msg_len(m_in.m11_i3);
		tmp->data = (char *) malloc(tmp->dataLen);
		sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) tmp->data, tmp->dataLen);
		tmp->senderId = m_in.m_source;
		tmp->expiryts = m_in.m11_t1;
		tmp->priority = m_in.m11_i1;
		tmp->rests = clock_time();
		tmp->recieverCount = m_in.m11_i2;
		tmp->recieverIds = (int *) malloc(tmp->recieverCount * sizeof(int));
		sys_datacopy(who_e, (vir_bytes)  m_in.m11_e1, SELF,(vir_bytes) tmp->recieverIds, tmp->recieverCount * sizeof(int));
	}
	return tmp;
}

/**
 *  Avoid buffer overrun
 */
int cap_msg_len(int len) {
	printf("WARN: Message length is more than %d, message will be truncated.", QIPC_MAX_MSG_LEN);
	return ( len > QIPC_MAX_MSG_LEN) ? QIPC_MAX_MSG_LEN : len;
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
