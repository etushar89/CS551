#ifndef ARECEIVER_H
#define ARECEIVER_H

#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define async_recieve _async_receive

void async_recieve( char *qname, int recid, int senderId)
{
	message m;
	
	m.m11_i3 = recid;
	m.m11_ca1 = qname;
 
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

	int ret = _syscall(PM_PROC_NR, 70, &m);

	if(ret == 9)
		printf("\nERROR:Queue %s does not exist", qname);
	else if (ret == 6)
		printf("\nMessage for me is %s", data);
	else if (ret == 7)
	 	printf("\nNo message for this receiver in queue %s", qname);
	else if(ret==14)
		printf("\nERROR: Permission denied");
}	

#endif
