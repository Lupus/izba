/* Empty <sys/syscall.h> for the MinGW erofs-utils build: lib/uuid.c
 * includes it unconditionally on the !HAVE_SYS_RANDOM_H path, but the
 * syscall(__NR_getrandom) call itself is `#if defined(__linux__)`-guarded —
 * on MinGW upstream's own rand() fallback takes over. */
#ifndef EROFS_MINGW_SYS_SYSCALL_H
#define EROFS_MINGW_SYS_SYSCALL_H
#endif
