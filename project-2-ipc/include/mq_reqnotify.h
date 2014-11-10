#ifndef NOTIFY_H
#define NOTIFY_H

#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define mq_reqnotify _mq_reqnotify
int notification_alert = 0;
void notifyhandler(int sig) {

		// Alert Received for requested notification
		notification_alert = 1;
		printf("\nINFO: Message Notification");
}

int mq_reqnotify(int senderno){
	message m;
	m.m10_i1 = senderno;
	int ret;
	signal(SIGUSR1, notifyhandler);
	signal(SIGINT, notifyhandler);
	ret = _syscall(PM_PROC_NR, REQNOTIFY, &m);
	
	return ret;
}

#endif