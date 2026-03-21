/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2013 Friedrich Schöller <hans@schoeller.se>
 *                1998-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef _WIN32

#include "win32_compat.h"   /* provides hans_fd_t, uint32_t, bool, VTUN_DEV_LEN */

#define VTUN_DEV_LEN 100

#else /* !_WIN32 */

#include <stdint.h>
#include <stdbool.h>

/* hans_fd_t = int on POSIX */
#ifndef HANS_FD_T_DEFINED
#define HANS_FD_T_DEFINED
typedef int hans_fd_t;
#endif

#define VTUN_DEV_LEN 20

#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

    hans_fd_t   tun_open(char *dev);
    int         tun_close(hans_fd_t fd, char *dev);
    int         tun_write(hans_fd_t fd, char *buf, int len);
    int         tun_read(hans_fd_t fd, char *buf, int len);
    const char *tun_last_error(void);

#ifdef _WIN32
    bool tun_set_ip(hans_fd_t fd, uint32_t local, uint32_t network, uint32_t netmask);
#endif

#ifdef __cplusplus
}
#endif
