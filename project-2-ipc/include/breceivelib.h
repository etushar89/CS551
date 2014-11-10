#ifndef BRECEIVER_H
#define BRECEIVER_H

#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define blocking_recieve _blocking_receive

int receiverid = 0;
char *Qname = NULL;
int senId = 0;
char data[50];

void inthandler_rec(int sig) {
	printf("\nMessage arrived for me !\n");
	message m;

	m.m11_i3 = receiverid;
	m.m11_ca1 = Qname;
	m.m11_i2 = (senId == -1) ? 0 : 1;
	m.m11_i1 = senId;

	m.m11_ca2 = data;

	int ret =  _syscall(PM_PROC_NR, 110, &m);
	if (ret == 7) 
		printf("\nBLOCKING RECEIVE FATAL: no message\n");
	else if(ret == 6)
		printf("\nMessage is %s", data);
}

void blocking_recieve( char *qname, int recid, int senderId)
{
	message m;

	strcpy(data, "\0");
	
	m.m11_i3 = receiverid = recid;
	m.m11_ca1 = Qname =qname; 
	if (senderId != -1)
	{
		m.m11_i2 = 1;
		m.m11_i1 = senId = senderId;
	}
	else
	{
		m.m11_i2 = 0;
		m.m11_i1 = senId = -1;
	}      
	m.m11_ca2 = data;

	int ret = _syscall(PM_PROC_NR, 110, &m);
	if(ret == 9)
		printf("\n Queue %s does not exist", qname);
	else if (ret == 6)
		printf("\nMessage for me is %s", data);
	else if(ret == 13) {
		printf("\nNo message for this receiver");
		printf("\nBlocking this receiver will lead to DEADLOCK");
		printf("\nRequest denied");
	}		
	else if (ret == 7)
	 {
		// no message for this receiver
		// go to sleep until message arrives
		printf("\nNo message for me.. Going to sleep\n");

		static volatile sig_atomic_t sigreceived =0;

		signal(SIGUSR1, inthandler_rec);
		
		sigset_t mask, oldmask;
		sigemptyset (&mask);
		sigaddset (&mask, SIGUSR1);
	
		sigprocmask (SIG_BLOCK, &mask, &oldmask);
		if (sigreceived == 0)
  			sigsuspend (&oldmask);
		sigprocmask (SIG_UNBLOCK, &mask, NULL);
        }
	
}	

#endif
