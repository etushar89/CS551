#ifndef SEND_ALL_H
#define SEND_ALL_H

#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define mq_send _mq_send
int blocking_return = 0;
void ipthandler(int sig) {
	if(sig == SIGUSR1){
		printf("\nINFO: Blocking send completed ");
		blocking_return = 1;
	}
	else if (sig == SIGUSR2){
		printf("\nError: Message not added ");
		blocking_return = 0;
	}
}

int mq_send(char *qname, int senid, int *ids, int totalids, char *data, int priority, long timestamp) {
	message m;
	int ret = 3;
	
	
	signal(SIGUSR1,ipthandler);
	signal(SIGUSR2,ipthandler);
	
	m.m11_ca1 = qname;
	m.m11_ca2 = data;
	
	m.m11_i3 = senid;

	m.m11_i2 = priority;
	m.m11_i1   = totalids;

	m.m11_t1 = (time(NULL) + timestamp);
	m.m11_e1 = ids;

	ret = _syscall(PM_PROC_NR, 69, &m);

	printf("\nINFO: Send blocking %d", getpid());	
		sigset_t mask, oldmask;
		sigfillset(&mask);
		sigdelset(&mask, SIGUSR2);
		sigdelset(&mask, SIGUSR1);
		sigdelset(&mask, SIGINT);
		sigsuspend(&mask);
	
	printf("Blocking retunr = %d", blocking_return);
	return blocking_return;
}
	
#endif
