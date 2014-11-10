#ifndef _QLIB_H
#define _QLIB_H

#include<lib.h>
#include <stdio.h>
#include <string.h>

#define open_queue     _open_queue
#define close_queue    _close_queue
#define setattr_queue  _setattr_queue
#define getattr_queue  _getattr_queue

int open_queue(char *qname, char *new_name) 
{
	message m;

	m.m11_ca1=qname; //q name
 	m.m11_i1 = strlen(qname); //q name len
 	m.m11_i2 = 5; //q capacity
 	m.m11_i3 = 0; //q type (non)blocking
 
	int i = _syscall(PM_PROC_NR, 44, &m);
	new_name = m.m11_ca1;
	
	return i;

}

int close_queue(char *qname)
{
	message m;

 	m.m11_ca1=qname; //q name
 	m.m11_i1 = strlen(qname);   //q name len
 
	return(_syscall(PM_PROC_NR, 45, &m));
}

int getattr_queue(char *qname, int *capacity, int *type) 
{
	message m;

        m.m11_ca1=qname; //q name
        m.m11_i1 = strlen(qname); //q name len

	int ret = _syscall(PM_PROC_NR, 57, &m);
	if (ret != 11)
		return -1;

	*capacity = m.m2_i1;
	*type = m.m2_i2;

	return 0;
}

int setattr_queue(char *qname, int capacity, int type)
{
	 message m;

        m.m11_ca1=qname; //q name
        m.m11_i1 = strlen(qname); //q name len

	m.m11_i2 = capacity;
	m.m11_i3 = type;

	return(_syscall(PM_PROC_NR, 56, &m));

}
 
#endif

