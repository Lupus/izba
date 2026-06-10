/* Minimal <sys/ioctl.h> for the MinGW erofs-utils build: block-device
 * ioctls never apply on Windows (output is always a regular file). */
#ifndef EROFS_MINGW_SYS_IOCTL_H
#define EROFS_MINGW_SYS_IOCTL_H
#include <errno.h>
static inline int ioctl(int fd, unsigned long req, ...)
{
	(void)fd; (void)req;
	errno = ENOTSUP;
	return -1;
}
#endif
