#ifndef NONBLOCK_ALL_H
#define NONBLOCK_ALL_H

#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define async_send _async_send
#define async_receive _async_receive

int async_send(char *qname, int senid, int *ids, int totalids, char *data, int priority, int timestamp) {
	message m;
	
	//strcpy(m.m11_ca1, data);
	m.m11_ca1 = qname;
	m.m11_ca2 = data;
	
	//m.m11_i3 = strlen(m.m11_ca2);
	m.m11_i3 = senid;

	m.m11_i2 = priority;
	m.m11_i1   = totalids;

	m.m11_t1 = (time(NULL) + timestamp);
	m.m11_e1 = ids;

	return (_syscall(PM_PROC_NR, 69, &m));
	
}
	
#endif
