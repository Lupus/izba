/* Companion to erofs_mingw.h — linked into the MinGW build via LIBS=. */
#include "erofs_mingw.h"
#include "regex.h"
#include <fcntl.h>
#include <io.h>
#include <string.h>
#include <stdarg.h>

/* CRT text-mode translation would corrupt the image; force binary mode for
 * every fd (mingw-w64 reads _CRT_fmode at startup). */
unsigned int _CRT_fmode = _O_BINARY;

static void die_stub(const char *api)
{
	fprintf(stderr,
		"mkfs.erofs(win32): %s reached — non-tar path is unsupported\n",
		api);
	exit(70);
}

int lstat(const char *path, struct stat *st)
{
	(void)path; (void)st;
	die_stub("lstat");
	return -1;
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
	(void)path; (void)buf; (void)bufsiz;
	die_stub("readlink");
	return -1;
}

char *realpath(const char *path, char *resolved_path)
{
	(void)path; (void)resolved_path;
	die_stub("realpath");
	return NULL;
}

/* POSIX regex (compat regex.h): --exclude-regex / compress-hints only */
int regcomp(regex_t *preg, const char *pattern, int cflags)
{
	(void)preg; (void)pattern; (void)cflags;
	die_stub("regcomp");
	return -1;
}

int regexec(const regex_t *preg, const char *string, size_t nmatch,
	    regmatch_t pmatch[], int eflags)
{
	(void)preg; (void)string; (void)nmatch; (void)pmatch; (void)eflags;
	die_stub("regexec");
	return -1;
}

size_t regerror(int errcode, const regex_t *preg, char *errbuf,
		size_t errbuf_size)
{
	(void)errcode; (void)preg; (void)errbuf; (void)errbuf_size;
	die_stub("regerror");
	return 0;
}

void regfree(regex_t *preg)
{
	(void)preg;
	die_stub("regfree");
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	__int64 cur = _telli64(fd);
	int n;

	if (cur < 0 || _lseeki64(fd, offset, SEEK_SET) < 0)
		return -1;
	n = _read(fd, buf, (unsigned int)count);
	_lseeki64(fd, cur, SEEK_SET);
	return n;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	__int64 cur = _telli64(fd);
	int n;

	if (cur < 0 || _lseeki64(fd, offset, SEEK_SET) < 0)
		return -1;
	n = _write(fd, buf, (unsigned int)count);
	_lseeki64(fd, cur, SEEK_SET);
	return n;
}

int fsync(int fd)
{
	return _commit(fd);
}

char *strndup(const char *s, size_t n)
{
	size_t len = 0;
	char *p;

	while (len < n && s[len])
		len++;
	p = malloc(len + 1);
	if (!p)
		return NULL;
	memcpy(p, s, len);
	p[len] = '\0';
	return p;
}

int asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int len, ret;

	va_start(ap, fmt);
	len = _vscprintf(fmt, ap);
	va_end(ap);
	if (len < 0)
		return -1;
	*strp = malloc((size_t)len + 1);
	if (!*strp)
		return -1;
	va_start(ap, fmt);
	ret = vsnprintf(*strp, (size_t)len + 1, fmt, ap);
	va_end(ap);
	if (ret < 0) {
		free(*strp);
		*strp = NULL;
	}
	return ret;
}

int fchmod(int fd, mode_t mode)
{
	/* no POSIX file modes on Windows; no-op success is the platform
	 * semantic (callers only touch unlinked temp files) */
	(void)fd; (void)mode;
	return 0;
}
