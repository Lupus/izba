/* Force-included (gcc -include) into every erofs-utils translation unit of
 * the x86_64-w64-mingw32 build.  This port is TAR-MODE ONLY: POSIX
 * directory-walk APIs are declared here and abort loudly in erofs_mingw.c —
 * reaching one means the invocation left the tar-mode path and the output
 * cannot be trusted.  Design: 2026-06-10-mkfs-erofs-windows-design.md §3.1 */
#ifndef EROFS_MINGW_COMPAT_H
#define EROFS_MINGW_COMPAT_H
#ifdef __MINGW32__

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error "erofs_mingw.h requires -D_FILE_OFFSET_BITS=64 (64-bit off_t)"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
/* Pull in mingw-w64's unistd.h NOW so its 32-bit ftruncate prototype lands
 * before our remap below; later #include <unistd.h> in erofs sources are
 * no-ops thanks to its include guard. */
#include <unistd.h>

typedef unsigned int uint;

/* dir-entry type constants (dir-walk mode only; never hit in tar-mode) */
#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12

#ifndef S_IFLNK
#define S_IFLNK  0xA000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

#ifndef _POSIX_OPEN_MAX
#define _POSIX_OPEN_MAX 16
#endif

/* device numbers come from ustar headers in tar-mode; the host filesystem's
 * are meaningless on Windows */
#define makedev(maj, min) (0)
#define major(dev) (0)
#define minor(dev) (0)

/* no POSIX user/group model; tar headers carry uid/gid */
static inline int getuid(void)  { return 0; }
static inline int getgid(void)  { return 0; }
static inline int geteuid(void) { return 0; }
static inline int getegid(void) { return 0; }

/* real shims (erofs_mingw.c) — used on the image-output path.
 * ftruncate needs no shim: with _FILE_OFFSET_BITS=64 mingw's unistd.h
 * (included above) remaps it to libmingwex's 64-bit ftruncate64. */
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
int fsync(int fd);
char *strndup(const char *s, size_t n);
int asprintf(char **strp, const char *fmt, ...);
int getpagesize(void); /* real function in libmingwex, just undeclared */
/* POSIX file modes don't exist on Windows; succeeding as a no-op is the
 * correct platform semantic (only used on unlinked temp files anyway). */
int fchmod(int fd, mode_t mode);

/* loud abort stubs (erofs_mingw.c) — dir-walk mode only */
int lstat(const char *path, struct stat *st);
ssize_t readlink(const char *path, char *buf, size_t bufsiz);
char *realpath(const char *path, char *resolved_path);

#endif /* __MINGW32__ */
#endif
