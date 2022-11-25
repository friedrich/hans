#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include <ctype.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if_utun.h>
#include <netinet/ip.h>

#include "tun_dev.h"

/*
 * Allocate TUN device, returns opened fd.
 * Stores dev name in the first arg(must be large enough).
 */
int tun_open(char *ifname)
{
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd = -1;
    int err = 0;
    int unit = 0;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -1;
    }

    /* Look up the kernel controller ID for utun devices. */
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

    err = ioctl(fd, CTLIOCGINFO, &info);
    if (err != 0) {
        close(fd);
        return -1;
    }

    /* Connecting to the socket creates the utun device. */
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;

    /* Look for a first available utun device */
    for (unit = 1; unit < 50; unit++) {
        addr.sc_unit = unit;
        err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
        if (err == 0) {
            break;
        }
    }
    if (err != 0) {
        close(fd);
        return -1;
    }

    /* Retrieve the assigned interface name. */
    socklen_t ifname_len = VTUN_DEV_LEN;
    err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
    if (err != 0) {
        close(fd);
        return -1;
    }

    /* Set FD_CLOEXEC flag on file descriptor.
     * This stops it from being inherited by system() calls.
     */
    if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int tun_close(int fd, char *dev)
{
    return close(fd);
}

/* Read/write frames from TUN device */
int tun_write(int fd, char *buf, int len)
{
    u_int32_t type = htonl(AF_INET);
    struct iovec iv[2];
    int wlen;

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    if ((wlen = writev(fd, iv, 2)) > 0)
        return wlen - sizeof(type);
    return wlen;
}

int tun_read(int fd, char *buf, int len)
{
    struct iovec iv[2];
    u_int32_t type;
    register int rlen;

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    if ((rlen = readv(fd, iv, 2)) > 0)
        return rlen - sizeof(type);
    else
        return rlen;
}

const char *tun_last_error()
{
    return strerror(errno);
}
