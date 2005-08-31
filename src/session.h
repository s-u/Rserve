#ifndef SESSION_H__
#define SESSION_H__

struct sSession {
	unsigned char key[16];
	int s;
};

struct sSession *new_session(char key[16]);
struct sSession *find_session(char key[16]);
void free_session(char key[16]);

/* functions for walking thorugh sessions.
   warning: next_session becomes invalid if new_session or
            free_session is called between first_session and
	    and any subsequent next_session
*/
struct sSession *first_session();
struct sSession *next_session(struct sSession* current);

#endif
