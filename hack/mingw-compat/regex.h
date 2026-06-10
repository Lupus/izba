/* Minimal <regex.h> for the MinGW erofs-utils build.  POSIX regexes are
 * only used by --exclude-regex (dir-walk mode) and compress-hints files —
 * both off the tar-mode path — so every function aborts loudly via
 * die_stub() in erofs_mingw.c. */
#ifndef EROFS_MINGW_REGEX_H
#define EROFS_MINGW_REGEX_H
#include <stddef.h>

typedef struct {
	void *unused;
} regex_t;

typedef long regoff_t;

typedef struct {
	regoff_t rm_so;
	regoff_t rm_eo;
} regmatch_t;

#define REG_EXTENDED 1
#define REG_ICASE    2
#define REG_NOSUB    4
#define REG_NEWLINE  8

#define REG_NOMATCH  1

int regcomp(regex_t *preg, const char *pattern, int cflags);
int regexec(const regex_t *preg, const char *string, size_t nmatch,
	    regmatch_t pmatch[], int eflags);
size_t regerror(int errcode, const regex_t *preg, char *errbuf,
		size_t errbuf_size);
void regfree(regex_t *preg);

#endif
