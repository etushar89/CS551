#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define blocking_recieve _blocking_recieve

#define SIG_TEST 44

void inthandler(int sig) {
	printf("\n in signal handler\n");
	
}
int blocking_recieve(int recieverId, int priority)
{
	/*message m;
	int i;
	while(1) 
	{       
        	m.m3_i1 = recieverId;
        	m.m3_i2 = priority;

        	if(!_syscall(PM_PROC_NR, 44, &m))
		{
			printf("\nfound!");
			break;
		}		
		printf("\n\n looping");
		sleep(5);
	}*/

	message m;
	m.m3_i1 = recieverId;
        m.m3_i2 = priority;

	if(_syscall(PM_PROC_NR, 44, &m)) {	
	static volatile sig_atomic_t sigreceived =0;

	//signal(SIGUSR1, inthandler);
	signal(SIG_TEST, inthandler);

	sigset_t mask, oldmask;
	sigemptyset (&mask);
	sigaddset (&mask, SIGUSR1);
	
	sigprocmask (SIG_BLOCK, &mask, &oldmask);
	if (sigreceived == 0)
  		sigsuspend (&oldmask);
	sigprocmask (SIG_UNBLOCK, &mask, NULL);
        //printf("\n data is %s", m.m3_p1);
	}
}
