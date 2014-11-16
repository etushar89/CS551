/*
 * qipcparser.c
 *
 *  Created on: 15-Nov-2014
 *      Author: matrix
 */
#include "pm.h"

gAuthEntity* secure_q_gAuth_list[MAX_AUTH_ENTITIES];
uAuthEntity* secure_q_uAuth_list[MAX_AUTH_ENTITIES];
gid_t denied_public_q_gauth[MAX_AUTH_ENTITIES];
uid_t denied_public_q_uauth[MAX_AUTH_ENTITIES];

int secure_q_gAuth_count;
int secure_q_uAuth_count;
int denied_public_q_gauth_count;
int denied_public_q_uauth_count;

char line[256], *lineptr;
unsigned linenr;

void tokenize_list(char *type, char *list) {
	int ids[MAX_LENGTH];
	char str[MAX_LENGTH];
	int count = 0, i, k;

	strcpy(str, "\0");
	k = 0;

	for (i = 0; list[i] != '\0'; i++) {
		if (list[i] == ',') {
			str[k] = '\0';
			printf("\n\t str %s", str);
			ids[count++] = atoi(str);
			k = 0;
			i++;
		}
		str[k++] = list[i];
	}

	if (str) {
		str[k] = '\0';
		ids[count++] = atoi(str);
	}

	if (strcmp(type, "write_groups") == 0 || strcmp(type, "read_groups") == 0) {

		gAuthEntity* temp;

		for (i = 0; i < count; i++) {
			temp = (gAuthEntity*) malloc(sizeof(gAuthEntity));
			temp->gid = ids[i];
			if (strcmp(type, "write_groups") == 0)
				temp->auth = Q_CREATE | Q_DROP | Q_WRITE;
			else
				temp->auth = Q_READ;

			secure_q_gAuth_list[secure_q_gAuth_count++] = temp;
		}
	}

	else if (strcmp(type, "write_users") == 0
			|| strcmp(type, "read_users") == 0) {

		uAuthEntity* temp;

		for (i = 0; i < count; i++) {
			temp = (uAuthEntity*) malloc(sizeof(uAuthEntity));
			temp->uid = ids[i];
			if (strcmp(type, "write_users") == 0)
				temp->auth = Q_CREATE | Q_DROP | Q_WRITE;
			else
				temp->auth = Q_READ;

			secure_q_uAuth_list[secure_q_uAuth_count++] = temp;
		}

	}

	else if (strcmp(type, "exclude_groups") == 0) {

		for (i = 0; i < count; i++)
			denied_public_q_gauth[denied_public_q_gauth_count++] = ids[i];
	}

	else if (strcmp(type, "exclude_users") == 0) {

		for (i = 0; i < count; i++)
			denied_public_q_uauth[denied_public_q_uauth_count++] = ids[i];
	}

	//Give all permissions to root group
	gAuthEntity *tmp_g = (gAuthEntity*) malloc(sizeof(gAuthEntity));
	tmp_g->gid = 0;
	tmp_g->auth = Q_CREATE | Q_WRITE | Q_READ | Q_DROP;
	secure_q_gAuth_list[secure_q_gAuth_count++] = tmp_g;

	//Give all permissions to root user
	uAuthEntity *tmp_u = (uAuthEntity*) malloc(sizeof(uAuthEntity));
	tmp_u->uid = 0;
	tmp_u->auth = Q_CREATE | Q_WRITE | Q_READ | Q_DROP;
	secure_q_uAuth_list[secure_q_uAuth_count++] = tmp_u;
}

int parse_secure() {
	int fp;
	char string[MAX_LENGTH], var[MAX_LENGTH], val[MAX_LENGTH];
	int secure = 2, i;

	if ((fp = open("/etc/secure.conf", O_RDONLY)) == -1)
		printf("");

	while (nextline(fp) != 0) {
		strcpy(string, "\0");
		strcpy(var, "\0");
		strcpy(val, "\0");

		strncpy(string, lineptr, MAX_LENGTH);
		if (string[strlen(string) - 1] == '\n')
			string[strlen(string) - 1] = '\0';

		if (string[0] == '[' && strcmp(string, "[secure]") == 0) {
			secure = 1;
			continue;
		} else if (string[0] == '[' && strcmp(string, "[public]") == 0) {
			secure = 0;
			continue;
		}

		// ignore comments
		if (string[0] == '#')
			continue;

		for (i = 0; string[i] != '='; i++)
			var[i] = string[i];

		var[i] = '\0';
		printf("\n\t var %s", var);

		if (var) {
			strcpy(val, (string + i + 1));
			if (!val) {
				printf("\nERROR: no value present for %s", var);
				return -1;
			}

			if ((strcmp(var, "write_groups") == 0
					|| strcmp(var, "read_groups") == 0
					|| strcmp(var, "write_users") == 0
					|| strcmp(var, "read_users") == 0) && !secure) {
				printf("\nERROR: %s not allowed in [public]", var);
				return -1;
			}

			if ((strcmp(var, "exclude_groups") == 0
					|| strcmp(var, "exclude_users") == 0) && secure) {
				printf("\nERROR: %s not allowed in [secure]", var);
				return -1;
			}

			tokenize_list(var, val);
		}
	}
	return 0;
}

int nextline(int fp) {
	/* Read a line from the configuration file, to be used by subsequent
	 * token() calls. Skip empty lines, and lines where the first character
	 * after leading "whitespace" is '#'. The last line of the file need
	 * not be terminated by a newline. Return 1 if a line was read in
	 * successfully, and 0 on EOF or error.
	 */
	char *lp, c;
	int r, skip;

	lineptr = lp = line;
	linenr++;
	skip = -1;

	while ((r = read(fp, &c, 1)) == 1) {
		if (c == '\n') {
			if (skip == 0)
				break;

			linenr++;
			skip = -1;
			continue;
		}

		if (skip == -1 && c > ' ')
			skip = (c == '#');

		if (skip == 0 && lp < (char *) line + sizeof(line) - 1)
			*lp++ = c;
	}

	*lp = 0;
	return (r == 1 || lp != line);
}

void print_lists() {
	int i;
	gAuthEntity *gList;
	uAuthEntity *uList;

	if (secure_q_gAuth_count) {
		printf("\n\nGroup List ");
		for (i = 0; i < secure_q_gAuth_count; i++) {
			gList = secure_q_gAuth_list[i];
			printf("\nGroup id = %d", gList->gid);
			printf("\nGroup mode = %d", gList->auth);
		}
	}

	if (secure_q_uAuth_count) {
		printf("\n\nUser List ");
		for (i = 0; i < secure_q_uAuth_count; i++) {
			uList = secure_q_uAuth_list[i];
			printf("\nUser id = %d", uList->uid);
			printf("\nUser mode = %d", uList->auth);
		}
	}

	if (denied_public_q_gauth_count) {
		printf("\n\nExcluded group list");
		for (i = 0; i < denied_public_q_gauth_count; i++)
			printf("\nGroup id : %d", denied_public_q_gauth[i]);
	}

	if (denied_public_q_uauth_count) {
		printf("\n\nExcluded user list");
		for (i = 0; i < denied_public_q_uauth_count; i++)
			printf("\nUser id : %d", denied_public_q_uauth[i]);
	}

	printf("\n\n");

}
