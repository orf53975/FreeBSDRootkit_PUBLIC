#include "electronics_kit.h"

//Following fd functions taken from https://lists.freebsd.org/pipermail/freebsd-hackers/2007-May/020625.html

int filewriter_closelog(struct thread *td, int fd)
{

	if(fd)
	{
		struct close_args fdtmp;
		fdtmp.fd = fd;
		return sys_close(td, &fdtmp);
	}
	return 0;
}

int filewriter_openlog(struct thread *td, int *fd, char *path)
{

	int error;

	// struct filedesc * fdp = td->td_proc->p_fd;
	// FILEDESC_XLOCK(fdp);
	// u_short saved_umask = fdp->fd_cmask;
	// fdp->fd_cmask = 0;
	// FILEDESC_XUNLOCK(fdp);

	error = kern_openat(td, AT_FDCWD, path, UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0777);

	// FILEDESC_XLOCK(fdp);
	// fdp->fd_cmask = saved_umask;
	// FILEDESC_XUNLOCK(fdp);

	if (error)
		return error;
	*fd = td->td_retval[0];
	return error;


}

int filewriter_writelog(struct thread *td, int fd, char *line, u_int len)
{
	struct uio auio;
	struct iovec aiov;
	int err;

	bzero(&aiov, sizeof(aiov));
	bzero(&auio, sizeof(auio));

	aiov.iov_base = line;
	aiov.iov_len = len;

	auio.uio_iov = &aiov;
	auio.uio_offset = 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;

	auio.uio_td = td;

	err = kern_writev(td, fd, &auio);


	return err;
}
