/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2013 Friedrich Schöller <hans@schoeller.se>
 *                2002-2005 Ivo Timmermans,
 *                2002-2011 Guus Sliepen <guus@tinc-vpn.org>
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

#include "tun_dev.h"

#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>

#include <w32api/windows.h>
#include <w32api/winioctl.h>

#define TAP_WIN_CONTROL_CODE(request,method) CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_MAC               TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION           TAP_WIN_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU               TAP_WIN_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_INFO              TAP_WIN_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      TAP_WIN_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      TAP_WIN_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE          TAP_WIN_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   TAP_WIN_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN            TAP_WIN_CONTROL_CODE (10, METHOD_BUFFERED)
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define SYSDEVICEDIR      "\\Device\\"
#define USERDEVICEDIR     "\\DosDevices\\Global\\"
#define TAP_WIN_SUFFIX    ".tap"

struct adapter_info
{
    int reader_read_fd, reader_write_fd;
    HANDLE reader_thread;
    HANDLE adapter_handle;
};

#define ERROR_BUFFER_SIZE 1024

char error_buffer[ERROR_BUFFER_SIZE];

static void error(char *format, ...)
{
    va_list vl;
    va_start(vl, format);
    vsnprintf(error_buffer, ERROR_BUFFER_SIZE, format, vl);
    va_end(vl);
}

static void noerror(void)
{
    *error_buffer = 0;
}

static const char *winerror(int err)
{
    static char buf[1024], *ptr;

    ptr = buf + sprintf(buf, "(%d) ", err);

    if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ptr, sizeof(buf) - (ptr - buf), NULL)) {
        strcpy(ptr, "(unable to format errormessage)");
    };

    if((ptr = strchr(buf, '\r')))
        *ptr = '\0';

    return buf;
}

static struct adapter_info *get_adapter_info_from_fd(int fd)
{
    static struct adapter_info single_adapter_info = {
        .reader_read_fd = -1,
        .reader_write_fd = -1,
        .reader_thread = INVALID_HANDLE_VALUE,
        .adapter_handle = INVALID_HANDLE_VALUE
    };
    return &single_adapter_info;
}

static HANDLE open_tap_adapter(char *name)
{
    HKEY connections_key, adapter_key;
    int adapter_index, error_code;
    char regpath[1024];
    char adapter_id[VTUN_DEV_LEN];
    char adapter_path[1024];
    char adapter_name[1024];
    HANDLE adapter_handle = INVALID_HANDLE_VALUE;
    DWORD len;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &connections_key) != ERROR_SUCCESS)
    {
        error("opening registry: %s", winerror(GetLastError()));
        return INVALID_HANDLE_VALUE;
    }

    for (adapter_index = 0; ; adapter_index++)
    {
        len = sizeof(adapter_id);
        if (RegEnumKeyEx(connections_key, adapter_index, adapter_id, &len, 0, 0, 0, NULL) != ERROR_SUCCESS)
            break;

        snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapter_id);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS)
            continue;
        len = sizeof(adapter_name);
        if (RegQueryValueEx(adapter_key, "Name", 0, 0, adapter_name, &len) != ERROR_SUCCESS)
        {
            RegCloseKey(adapter_key);
            continue;
        }
        RegCloseKey(adapter_key);

        if (name && name[0] && strcmp(name, adapter_name) && strcmp(name, adapter_id))
            continue;

        snprintf(adapter_path, sizeof(adapter_path), USERMODEDEVICEDIR "%s" TAP_WIN_SUFFIX, adapter_id);

        adapter_handle = CreateFile(adapter_path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
        if (adapter_handle != INVALID_HANDLE_VALUE)
            break;
    }

    RegCloseKey(connections_key);

    if (adapter_handle == INVALID_HANDLE_VALUE)
    {
        error("could not open tap adapter");
        return INVALID_HANDLE_VALUE;
    }

    strncpy(name, adapter_name, VTUN_DEV_LEN);

    noerror();
    return adapter_handle;
}

static __stdcall DWORD reader_thread(LPVOID ptr)
{
    struct adapter_info *adapter_info = ptr;
    char buf[0xffff]; // maximum IPv4 packet size
    OVERLAPPED overlapped;
    DWORD len;
    int wait_result;

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEvent(NULL, true, false, NULL);

    while (true)
    {
        if (!ReadFile(adapter_info->adapter_handle, buf, sizeof(buf), &len, &overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                syslog(LOG_ERR, "error reading from tap adapter: %s", winerror(GetLastError()));
                return 1;
            }

            wait_result = WaitForSingleObjectEx(overlapped.hEvent, INFINITE, false);

            if (wait_result != WAIT_OBJECT_0)
            {
                syslog(LOG_ERR, "error waiting for tap adapter: %s", winerror(GetLastError()));
                return 1;
            }

            if (!GetOverlappedResult(adapter_info->adapter_handle, &overlapped, &len, true))
            {
                syslog(LOG_ERR, "error getting tap adapter reading result: %s", winerror(GetLastError()));
                return 1;
            }
        }

        write(adapter_info->reader_write_fd, buf, len);
    }
}

int tun_open(char *dev)
{
    struct adapter_info *adapter_info;
    int socket_pair[2];

    if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, socket_pair))
    {
        error("creating socket pair: %s", strerror(errno));
        return -1;
    }

    adapter_info = get_adapter_info_from_fd(socket_pair[0]);
    adapter_info->reader_read_fd = socket_pair[0];
    adapter_info->reader_write_fd = socket_pair[1];

    adapter_info->adapter_handle = open_tap_adapter(dev);
    if (adapter_info->adapter_handle == INVALID_HANDLE_VALUE)
    {
        tun_close(adapter_info->reader_read_fd, NULL);
        return -1;
    }

    adapter_info->reader_thread = CreateThread(NULL, 0, reader_thread, adapter_info, 0, NULL);
    if (adapter_info->reader_thread == INVALID_HANDLE_VALUE)
    {
        error("reader thread creation: %s", winerror(GetLastError()));
        tun_close(adapter_info->reader_read_fd, NULL);
        return -1;
    }

    return adapter_info->reader_read_fd;
}

int tun_close(int fd, char *dev)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);

    if (adapter_info->reader_thread != INVALID_HANDLE_VALUE)
    {
        TerminateThread(adapter_info->reader_thread, 0);
        adapter_info->reader_thread = INVALID_HANDLE_VALUE;
    }

    close(adapter_info->reader_read_fd);
    adapter_info->reader_read_fd = -1;

    close(adapter_info->reader_write_fd);
    adapter_info->reader_write_fd = -1;

    if (adapter_info->adapter_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(adapter_info->adapter_handle);
        adapter_info->adapter_handle = INVALID_HANDLE_VALUE;
    }

    return 0;
}

int tun_write(int fd, char *buf, int len)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);
    OVERLAPPED overlapped;
    DWORD written;

    memset(&overlapped, 0, sizeof(overlapped));

    if (!WriteFile(adapter_info->adapter_handle, buf, len, &written, &overlapped))
    {
        error("tap write: %s", winerror(GetLastError()));
        return -1;
    }

    return written;
}

int tun_read(int fd, char *buf, int len)
{
    len = read(fd, buf, len);
    if (len == -1)
        error("reader read: %s", strerror(errno));
    return len;
}

const char *tun_last_error()
{
    return error_buffer;
}

bool tun_set_ip(int fd, uint32_t local, uint32_t network, uint32_t netmask)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);
    uint32_t addresses[3];
    DWORD status;
    DWORD len;

    addresses[0] = htonl(local);
    addresses[1] = htonl(network);
    addresses[2] = htonl(netmask);

    if (!DeviceIoControl(adapter_info->adapter_handle, TAP_WIN_IOCTL_CONFIG_TUN,
        &addresses, sizeof(addresses), &addresses, sizeof(addresses), &len, NULL))
    {
        error("configuring tap addresses: %s", winerror(GetLastError()));
        return false;
    }

    status = true;
    if (!DeviceIoControl(adapter_info->adapter_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        error("enabling tap device: %s", winerror(GetLastError()));
        return false;
    }

    noerror();
    return true;
}
