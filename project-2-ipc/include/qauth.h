#ifndef QAUTH_H
#define QAUTH_H

#define auth_perm _auth_perm
#define ban_from_public _ban_from_public
#define add_admin_user _add_admin_user

#define Q_READ  00100
#define Q_WRITE 00200
#define Q_CREATE        00400
#define Q_DROP  01000

int auth_perm(int grporusr, int id, int perm) {
	message m;

	m.m11_i1 = id;
	m.m11_i2 = grporusr;

	switch(perm) 
	{
		case 1:
			m.m11_i3 = Q_CREATE;
			break;
		case 2:
			m.m11_i3 = Q_WRITE;
			break;
		case 3:
			m.m11_i3 = Q_READ;
			break;
	}

	int ret =  _syscall(PM_PROC_NR,AUTHPERM, &m);

	return ret;
}

int ban_from_public(int grporusr, int id) {
	message m;
 	m.m11_i1 = id;
	m.m11_i2 = grporusr;

	int ret = _syscall(PM_PROC_NR,BLACKLISTPUBLICQ, &m);

	return ret;
}

int add_admin_user(int grporusr, int id, int addordel) {
	message m;
	m.m11_i1 = id;
	m.m11_i2 = grporusr;
	m.m11_i3 = addordel;

	int ret = _syscall(PM_PROC_NR,ADDAUTHUSERS, &m);

	return ret;
}
 
#endif
