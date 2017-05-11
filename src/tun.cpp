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
#include <sstream>

#ifdef WIN32
#include <w32api/windows.h>
#endif

typedef ip IpHeader;

using std::string;

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

Tun::Tun(const string *device, int mtu)
{
    this->mtu = mtu;

    if (device)
        this->device = *device;

    this->device.resize(VTUN_DEV_LEN);
    fd = tun_open(&this->device[0]);
    this->device.resize(strlen(this->device.data()));

    if (fd == -1)
        throw Exception(string("could not create tunnel device: ") + tun_last_error());

    syslog(LOG_INFO, "opened tunnel device: %s", this->device.data());

    std::stringstream cmdline;

#ifdef WIN32
    cmdline << "netsh interface ipv4 set subinterface \"" << this->device
            << "\" mtu=" << mtu;
    winsystem(cmdline.str().data());
#else
    cmdline << "/sbin/ifconfig " << this->device << " mtu " << mtu;
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device mtu");
#endif
}

Tun::~Tun()
{
    tun_close(fd, &device[0]);
}

void Tun::setIp(uint32_t ip, uint32_t destIp)
{
    std::stringstream cmdline;
    string ips = Utility::formatIp(ip);
    string destIps = Utility::formatIp(destIp);

#ifdef WIN32
    cmdline << "netsh interface ip set address name=\"" << device << "\" "
            << "static " << ips << " 255.255.255.0";
    winsystem(cmdline.str().data());

    if (!tun_set_ip(fd, ip, ip & 0xffffff00, 0xffffff00))
        syslog(LOG_ERR, "could not set tun device driver ip address: %s", tun_last_error());
#elif LINUX
    cmdline << "/sbin/ifconfig " << device << " " << ips << " netmask 255.255.255.0";
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");
#else
    cmdline << "/sbin/ifconfig " << device << " " << ips << " " << destIps
            << " netmask 255.255.255.255";
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");
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
