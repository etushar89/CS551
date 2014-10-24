/* Data Store Server. 
 * This service implements a little publish/subscribe data store that is 
 * crucial for the system's fault tolerance. Components that require state
 * can store it here, for later retrieval, e.g., after a crash and subsequent
 * restart by the reincarnation server. 
 * 
 * Created:
 *   Oct 19, 2005	by Jorrit N. Herder
 */

#include "inc.h"	/* include master header file */
#include <minix/endpoint.h>

/* Allocate space for the global variables. */
static endpoint_t who_e; /* caller's proc number */
static int callnr; /* system call number */

/* Declare some local functions. */
static void get_work(message *m_ptr);
static void reply(endpoint_t whom, message *m_ptr);

/* SEF functions and variables. */
static void sef_local_startup(void);
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info);
int map_service(const struct rprocpub *rpub);

/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
int main(int argc, char **argv) {

	printf("############## From qIPC ######################");

	/* This is the main routine of this service. The main loop consists of
	 * three major activities: getting new work, processing the work, and
	 * sending the reply. The loop never terminates, unless a panic occurs.
	 */
	message m;
	int result;

	/* SEF local startup. */
	env_setargs(argc, argv);
	sef_local_startup();

	/* Main loop - get work and do it, forever. */
	while (TRUE) {

		//sleep(8000);

		/* Wait for incoming message, sets 'callnr' and 'who'. */
		get_work(&m);

		printf("############## From qIPC ######################");

		if (is_notify(callnr)) {
			printf("DS: warning, got illegal notify from: %d\n", m.m_source);
			result = EINVAL;
			goto send_reply;
		}

		switch (callnr) {
			      case DS_PUBLISH:
			          result = OK;
			          break;
			      case DS_RETRIEVE:
				  result = OK;
				  break;
			      case DS_RETRIEVE_LABEL:
				  result = OK;
				  break;
			      case DS_DELETE:
				  result = OK;
				  break;
			      case DS_SUBSCRIBE:
				  result = OK;
				  break;
			      case DS_CHECK:
				  result = OK;
				  break;
			      case COMMON_GETSYSINFO:
				  result = OK;
				  break;
			      default:
			          printf("DS: warning, got illegal request from %d : %d\n", m.m_source, callnr);
			          result = EINVAL;
		}

		send_reply:
		/* Finally send reply message, unless disabled. */
		if (result != EDONTREPLY) {
			result = OK;
			m.m_type = result; /* build reply message */
			reply(who_e, &m); /* send it away */
		}
	}
	return (OK); /* shouldn't come here */
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup() {
	/* Register init callbacks. */
	sef_setcb_init_fresh(sef_cb_init_fresh);
	sef_setcb_init_restart(sef_cb_init_fail);

	/* No live update support for now. */

	/* Let SEF perform startup. */
	sef_startup();
}

/*===========================================================================*
 *				get_work                                     *
 *===========================================================================*/
static void get_work(message *m_ptr /* message buffer */
) {
	int status = sef_receive(ANY, m_ptr); /* blocks until message arrives */
	if (OK != status)
		panic("failed to receive message!: %d", status);
	who_e = m_ptr->m_source; /* message arrived! set sender */
	callnr = m_ptr->m_type; /* set function call number */
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
static void reply(endpoint_t who_e, /* destination */
		message *m_ptr /* message buffer */
) {
	int s = send(who_e, m_ptr); /* send the message */
	if (OK != s)
		printf("DS: unable to send reply to %d: %d\n", who_e, s);
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
	int i, r;
	struct rprocpub rprocpub[18];

	/* Map all the services in the boot image. */
	if((r = sys_safecopyfrom(RS_PROC_NR, info->rproctab_gid, 0,
			(vir_bytes) rprocpub, sizeof(rprocpub))) != OK) {
		panic("sys_safecopyfrom failed: %d", r);
	}

	for(i=0;i < 18;i++) {
			if(rprocpub[i].in_use) {
				if((r = map_service(&rprocpub[i])) != OK) {
					panic("unable to map service: %d", r);
				}
			}
		}
	return(OK);
}

int map_service(rpub)
struct rprocpub *rpub;
{
/* Map a new service by registering a new acl entry if required.
	int i;

	 Stop right now if no pci device or class is found.
	if(rpub->pci_acl.rsp_nr_device == 0
		&& rpub->pci_acl.rsp_nr_class == 0) {
		return(OK);
	}

	 Find a free acl slot.
	for (i= 0; i<NR_DRIVERS; i++)
	{
		if (!pci_acl[i].inuse)
			break;
	}
	if (i >= NR_DRIVERS)
	{
		printf("PCI: map_service: table is full\n");
		return ENOMEM;
	}

	 Initialize acl slot.
	pci_acl[i].inuse = 1;
	pci_acl[i].acl = rpub->pci_acl;*/

	return(OK);
}
