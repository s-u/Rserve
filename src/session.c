/*
 *  implements a vector of session scructures accessible by a session key.
 *
 *  Author : Simon Urbanek
 *  Created: 2005/08/30
 *  License: GPL2
 *
 *  $Id$
 */

#include "config.h"
#include "session.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#else
#include <string.h>
#endif
#include <stdlib.h>

static struct sSession *session=0;
static int sessions=0;
static int sessions_allocated=0;

/* find a session */
struct sSession *find_session(char key[16]) {
	int i=0;
	while (i<sessions) {
		if (!memcmp(key,session[i].key,16))
			return &session[i];
		i++;
	}
	return 0;
}

#define sessions_increment 128

/* create a new session */
struct sSession *new_session(char key[16]) {
	if (!session) {
		sessions_allocated = sessions_increment;
		session = (struct sSession*) calloc(sessions_allocated, sizeof(struct sSession));
	} else if (sessions_allocated <= sessions) {
		sessions_allocated += sessions_increment;
		session = (struct sSession*) realloc(session, sessions_allocated * sizeof(struct sSession));
	}
	memset(&session[sessions], 0, sizeof(struct sSession));
	memcpy(&session[sessions].key, key, 16);
	return &session[sessions++];
}

/* remove session */
void free_session(char key[16]) {
	int i=0;
	while (i<sessions) {
		if (!memcmp(key,session[i].key,16)) {
			if (i<sessions-1)
				memmove(session+i, session+i+1, sizeof(struct sSession)*(sessions-i-1));
			sessions--;
			if (sessions_allocated>128 && sessions < sessions_allocated/2) {
				sessions_allocated = sessions_allocated/2 + 64;
				session = (struct sSession*) realloc(session, sessions_allocated * sizeof(struct sSession));
			}
			return;
		}
		i++;
	}
}

int total_sessions() { return sessions; }
struct sSession *first_session() { return session; }
struct sSession *next_session(struct sSession* current) {
	if (current<session || current>=session+sessions-1) return 0;
	return current+1;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
