/* Minimal <sys/mman.h> for the MinGW erofs-utils build.  The only live
 * caller (lib/fragments.c, compression-only feature) handles MAP_FAILED
 * gracefully with a read/write fallback, so mmap "failing" with ENOSYS is
 * functionally correct, not a lying stub.  kite_deflate.c's use is under
 * `#if TEST` and never compiled. */
#ifndef EROFS_MINGW_SYS_MMAN_H
#define EROFS_MINGW_SYS_MMAN_H
#include <errno.h>
#include <sys/types.h>

#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_SHARED  1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void *)-1)

static inline void *mmap(void *addr, size_t length, int prot, int flags,
			 int fd, off_t offset)
{
	(void)addr; (void)length; (void)prot; (void)flags;
	(void)fd; (void)offset;
	errno = ENOSYS;
	return MAP_FAILED;
}

static inline int munmap(void *addr, size_t length)
{
	(void)addr; (void)length;
	errno = EINVAL;
	return -1;
}

#endif
