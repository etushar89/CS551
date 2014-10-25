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
	sys_datacopy(SELF, (vir_bytes)  t->data, SELF,(vir_bytes) qipc_msg[0], 10);
	printf("Saved message: %s\n",qipc_msg[0]);
}

void do_receive_msg() {
	sys_datacopy(SELF, (vir_bytes)  qipc_msg[0], who_e,(vir_bytes) m_in.m11_ca1, 10);
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

qmsg * get_qipc_msg() {
	qmsg *tmp = (qmsg *) malloc(sizeof(qmsg));
	if(tmp!=NULL) {
		tmp->data = (char *) malloc(strlen(m_in.m11_ca1) * sizeof(char));
		sys_datacopy(who_e, (vir_bytes)  m_in.m11_ca1, SELF,(vir_bytes) tmp->data, 10);
		tmp->senderId = m_in.m_source;
		tmp->expiryts = m_in.m11_t1;
		tmp->priority = m_in.m11_i1;
		tmp->rests = clock_time();
		tmp->recieverCount = m_in.m11_i2;
		int i;
		for(i=0; i < (tmp->recieverCount);i++) {
			tmp->recieverIds[i] = *(m_in.m11_e1 + (i * sizeof(int)));
		}
	}
	return tmp;
}

time_t clock_time()
{
/* This routine returns the time in seconds since 1.1.1970.  MINIX is an
 * astrophysically naive system that assumes the earth rotates at a constant
 * rate and that such things as leap seconds do not exist.
 */

  register int k;
  clock_t uptime;
  time_t boottime;

  if ( (k=getuptime2(&uptime, &boottime)) != OK)
		panic("clock_time: getuptme2 failed: %d", k);

  return( (time_t) (boottime + (uptime/sys_hz())));
}
