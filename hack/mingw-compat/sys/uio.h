/* Minimal <sys/uio.h> for the MinGW erofs-utils build. */
#ifndef EROFS_MINGW_SYS_UIO_H
#define EROFS_MINGW_SYS_UIO_H
#include <sys/types.h>
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#endif
