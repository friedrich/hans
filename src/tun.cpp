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

#include "tun.h"
#include "exception.h"
#include "utility.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef WIN32
#include <w32api/windows.h>
#endif

typedef ip IpHeader;

using namespace std;

#ifdef WIN32
static void winsystem(char *cmd)
{
    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
    if (CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
    {
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
}
#endif

Tun::Tun(const char *device, int mtu)
{
    char cmdline[512];

    this->mtu = mtu;

    if (device != NULL)
    {
        strncpy(this->device, device, VTUN_DEV_LEN);
        this->device[VTUN_DEV_LEN-1] = 0;
    }
    else
        this->device[0] = 0;

    fd = tun_open(this->device);
    if (fd == -1)
        throw Exception(string("could not create tunnel device: ") + tun_last_error());

    syslog(LOG_INFO, "opened tunnel device: %s", this->device);

#ifdef WIN32
    snprintf(cmdline, sizeof(cmdline), "netsh interface ipv4 set subinterface \"%s\" mtu=%d", this->device, mtu);
    winsystem(cmdline);
#else
    snprintf(cmdline, sizeof(cmdline), "/sbin/ifconfig %s mtu %u", this->device, mtu);
    if (system(cmdline) != 0)
        syslog(LOG_ERR, "could not set tun device mtu");
#endif
}

Tun::~Tun()
{
    tun_close(fd, device);
}

void Tun::setIp(uint32_t ip, uint32_t destIp, bool includeSubnet)
{
    char cmdline[512];
    string ips = Utility::formatIp(ip);
    string destIps = Utility::formatIp(destIp);

#ifdef WIN32
    snprintf(cmdline, sizeof(cmdline), "netsh interface ip set address name=\"%s\" "
        "static %s 255.255.255.0", device, ips.c_str());
    winsystem(cmdline);

    if (!tun_set_ip(fd, ip, ip & 0xffffff00, 0xffffff00))
        syslog(LOG_ERR, "could not set tun device driver ip address: %s", tun_last_error());
#elif LINUX
    snprintf(cmdline, sizeof(cmdline), "/sbin/ifconfig %s %s netmask 255.255.255.0", device, ips.c_str());
    if (system(cmdline) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");
#else
    snprintf(cmdline, sizeof(cmdline), "/sbin/ifconfig %s %s %s netmask 255.255.255.255", device, ips.c_str(), destIps.c_str());
    if (system(cmdline) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");

    if (includeSubnet)
    {
        snprintf(cmdline, sizeof(cmdline), "/sbin/route add %s/24 %s", destIps.c_str(), destIps.c_str());
        if (system(cmdline) != 0)
            syslog(LOG_ERR, "could not add route");
    }
#endif
}

void Tun::write(const char *buffer, int length)
{
    if (tun_write(fd, (char *)buffer, length) == -1)
        syslog(LOG_ERR, "error writing %d bytes to tun: %s", length, tun_last_error());
}

int Tun::read(char *buffer)
{
    int length = tun_read(fd, buffer, mtu);
    if (length == -1)
        syslog(LOG_ERR, "error reading from tun: %s", tun_last_error());
    return length;
}

int Tun::read(char *buffer, uint32_t &sourceIp, uint32_t &destIp)
{
    int length = read(buffer);

    IpHeader *header = (IpHeader *)buffer;
    sourceIp = ntohl(header->ip_src.s_addr);
    destIp = ntohl(header->ip_dst.s_addr);

    return length;
}
