/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
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

#include "tunemu.h"

#include <syslog.h>

int tun_open(char *dev)
{
    return tunemu_open(dev);
}

int tun_close(int fd, char *dev)
{
    return tunemu_close(fd);
}

int tun_write(int fd, char *buf, int len)
{
    return tunemu_write(fd, buf, len);
}

int tun_read(int fd, char *buf, int len)
{
    return tunemu_read(fd, buf, len);
}

const char *tun_last_error()
{
    return tunemu_error;
}
