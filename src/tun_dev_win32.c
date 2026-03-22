/*
 *  Hans - IP over ICMP
 *  TAP adapter driver for native Windows / MSVC
 *
 *  Replaces tun_dev_cygwin.c for builds with MSVC (no Cygwin layer).
 *
 *  Architecture:
 *    - tun_open()  opens a TAP-Windows adapter and creates a TCP
 *                  loopback socket-pair so the main select()-loop can
 *                  wait on a real SOCKET descriptor.
 *    - A dedicated reader thread issues OVERLAPPED ReadFile() calls on
 *                  the TAP handle and forwards each packet to the write
 *                  end of the socket-pair via send().
 *    - tun_read()  calls recv() on the read end of the socket-pair.
 *    - tun_write() calls WriteFile() (with OVERLAPPED) on the TAP handle.
 *
 *  Requires TAP-Windows (OpenVPN TAP driver) to be installed.
 *
 *  Copyright (C) 2013 Friedrich Schöller <hans@schoeller.se>
 *  Windows native port (c) 2024
 */

#ifdef _WIN32

#include "win32_compat.h"
#include <winioctl.h>   /* CTL_CODE, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FILE_ANY_ACCESS */
#include "tun_dev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* TAP-Windows IOCTL codes                                             */
/* ------------------------------------------------------------------ */
#define TAP_WIN_CONTROL_CODE(req, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (req), (method), FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC               TAP_WIN_CONTROL_CODE(1,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION           TAP_WIN_CONTROL_CODE(2,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU               TAP_WIN_CONTROL_CODE(3,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_INFO              TAP_WIN_CONTROL_CODE(4,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE(5,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      TAP_WIN_CONTROL_CODE(6,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      TAP_WIN_CONTROL_CODE(7,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE          TAP_WIN_CONTROL_CODE(8,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   TAP_WIN_CONTROL_CODE(9,  METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN            TAP_WIN_CONTROL_CODE(10, METHOD_BUFFERED)

#define NETWORK_CONNECTIONS_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Network\\" \
    "{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR  "\\\\.\\Global\\"
#define TAP_WIN_SUFFIX     ".tap"

/* ------------------------------------------------------------------ */
/* Error buffer                                                        */
/* ------------------------------------------------------------------ */
#define ERROR_BUF_SIZE 1024
static char s_error_buf[ERROR_BUF_SIZE];

static void set_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s_error_buf, ERROR_BUF_SIZE, fmt, ap);
    va_end(ap);
}

static void clear_error(void) { s_error_buf[0] = '\0'; }

static const char *winerr_str(DWORD code)
{
    static char buf[512];
    char *p = buf;
    int  written = sprintf_s(buf, sizeof(buf), "(%lu) ", (unsigned long)code);
    if (written > 0) p += written;

    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, code, 0, p,
                        (DWORD)(sizeof(buf) - (size_t)(p - buf)), NULL))
        strcpy_s(p, sizeof(buf) - (size_t)(p - buf), "(unknown error)");

    /* strip trailing CR/LF */
    {
        size_t n = strlen(p);
        while (n && (p[n-1] == '\r' || p[n-1] == '\n'))
            p[--n] = '\0';
    }
    return buf;
}

/* ------------------------------------------------------------------ */
/* Per-adapter state (single instance — Hans opens one TUN device)    */
/* ------------------------------------------------------------------ */
static struct {
    SOCKET reader_sock;     /* main code reads packets here (select)  */
    SOCKET writer_sock;     /* reader thread writes packets here       */
    HANDLE reader_thread;   /* NULL = not running                      */
    HANDLE adapter_handle;
    HANDLE stop_event;      /* signaled by tun_close to request exit   */
} g_adapter = {
    INVALID_SOCKET,
    INVALID_SOCKET,
    NULL,
    INVALID_HANDLE_VALUE,
    NULL
};

/* ------------------------------------------------------------------ */
/* open_tap_adapter                                                    */
/*                                                                     */
/* Enumerates network adapters in the Windows registry and opens the   */
/* first TAP-Windows adapter found (or the one matching 'name').      */
/* On success fills 'name' with the adapter's friendly name and        */
/* returns a valid HANDLE; returns INVALID_HANDLE_VALUE on failure.   */
/* ------------------------------------------------------------------ */
static HANDLE open_tap_adapter(char *name)
{
    HKEY  conn_key   = NULL;
    HKEY  adap_key   = NULL;
    DWORD idx, len;
    char  adapter_id  [VTUN_DEV_LEN];
    char  adapter_name[VTUN_DEV_LEN];
    char  reg_path    [512];
    char  dev_path    [512];
    HANDLE handle = INVALID_HANDLE_VALUE;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY,
                      0, KEY_READ, &conn_key) != ERROR_SUCCESS) {
        set_error("opening registry: %s", winerr_str(GetLastError()));
        return INVALID_HANDLE_VALUE;
    }

    for (idx = 0; ; idx++) {
        len = sizeof(adapter_id);
        if (RegEnumKeyExA(conn_key, idx, adapter_id, &len,
                          NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        sprintf_s(reg_path, sizeof(reg_path),
                  "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapter_id);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path,
                          0, KEY_READ, &adap_key) != ERROR_SUCCESS)
            continue;

        len = sizeof(adapter_name);
        BOOL ok = (RegQueryValueExA(adap_key, "Name", 0, 0,
                                    (LPBYTE)adapter_name, &len) == ERROR_SUCCESS);
        RegCloseKey(adap_key);
        adap_key = NULL;

        if (!ok) continue;

        /* If a name was requested, match against friendly name or GUID */
        if (name && name[0] &&
            strcmp(name, adapter_name) != 0 &&
            strcmp(name, adapter_id)   != 0)
            continue;

        sprintf_s(dev_path, sizeof(dev_path),
                  USERMODEDEVICEDIR "%s" TAP_WIN_SUFFIX, adapter_id);

        handle = CreateFileA(dev_path,
                             GENERIC_READ | GENERIC_WRITE,
                             0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                             NULL);
        if (handle != INVALID_HANDLE_VALUE) {
            strncpy_s(name, VTUN_DEV_LEN, adapter_name, _TRUNCATE);
            break;
        }
    }

    RegCloseKey(conn_key);

    if (handle == INVALID_HANDLE_VALUE)
        set_error("could not open tap adapter (is TAP-Windows installed?)");

    return handle;
}

/* ------------------------------------------------------------------ */
/* reader_thread_proc                                                  */
/*                                                                     */
/* Reads packets from the TAP adapter using OVERLAPPED I/O and        */
/* forwards them to the socket-pair write end via send().             */
/* ------------------------------------------------------------------ */
static DWORD WINAPI reader_thread_proc(LPVOID param)
{
    (void)param;

    char       buf[0xFFFF]; /* maximum IPv4 packet size */
    OVERLAPPED ov;
    DWORD      len;
    HANDLE     events[2];

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        hans_syslog(LOG_ERR, "tap reader: CreateEvent failed: %s",
                    winerr_str(GetLastError()));
        return 1;
    }

    events[0] = ov.hEvent;
    events[1] = g_adapter.stop_event;

    for (;;) {
        ResetEvent(ov.hEvent);

        /* Issue the async read.  NULL for lpNumberOfBytesRead: on an
           overlapped handle that field is unreliable on sync completion;
           the real count always comes from GetOverlappedResult below. */
        if (!ReadFile(g_adapter.adapter_handle, buf, sizeof(buf), NULL, &ov)) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                hans_syslog(LOG_ERR, "tap reader: ReadFile error: %s",
                            winerr_str(err));
                break;
            }
        }

        /* Wait for either packet arrival or a shutdown request.
           This keeps the thread alive while the ReadFile is pending —
           TerminateThread is never called, so no ERROR_OPERATION_ABORTED. */
        DWORD w = WaitForMultipleObjects(2, events, FALSE, INFINITE);

        if (w == WAIT_OBJECT_0 + 1) {
            /* stop_event: cancel the pending read and exit cleanly */
            CancelIo(g_adapter.adapter_handle);
            GetOverlappedResult(g_adapter.adapter_handle, &ov, &len, TRUE);
            break;
        }
        if (w != WAIT_OBJECT_0) {
            hans_syslog(LOG_ERR, "tap reader: WaitForMultipleObjects error: %s",
                        winerr_str(GetLastError()));
            break;
        }

        if (!GetOverlappedResult(g_adapter.adapter_handle, &ov, &len, FALSE)) {
            hans_syslog(LOG_ERR, "tap reader: GetOverlappedResult error: %s",
                        winerr_str(GetLastError()));
            break;
        }

        if (send(g_adapter.writer_sock, buf, (int)len, 0) == SOCKET_ERROR) {
            hans_syslog(LOG_ERR, "tap reader: send error: %d",
                        WSAGetLastError());
            break;
        }
    }

    CloseHandle(ov.hEvent);
    return 0;
}

/* ================================================================== */
/* Public API                                                          */
/* ================================================================== */

hans_fd_t tun_open(char *dev)
{
    SOCKET sv[2];

    clear_error();

    if (win32_socketpair(sv) != 0) {
        set_error("creating socket pair: WSA %d", WSAGetLastError());
        return (hans_fd_t)INVALID_SOCKET;
    }
    g_adapter.reader_sock = sv[0];
    g_adapter.writer_sock = sv[1];

    g_adapter.stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_adapter.stop_event) {
        set_error("creating stop event: %s", winerr_str(GetLastError()));
        tun_close((hans_fd_t)g_adapter.reader_sock, NULL);
        return (hans_fd_t)INVALID_SOCKET;
    }

    g_adapter.adapter_handle = open_tap_adapter(dev);
    if (g_adapter.adapter_handle == INVALID_HANDLE_VALUE) {
        tun_close((hans_fd_t)g_adapter.reader_sock, NULL);
        return (hans_fd_t)INVALID_SOCKET;
    }

    /* Reader thread is NOT started here.  The TAP driver aborts any
       ReadFile while media status is FALSE.  Thread is started in
       tun_set_ip() only after TAP_WIN_IOCTL_SET_MEDIA_STATUS succeeds. */

    return (hans_fd_t)g_adapter.reader_sock;
}

int tun_close(hans_fd_t fd, char *dev)
{
    (void)fd;
    (void)dev;

    if (g_adapter.reader_thread != NULL) {
        /* Signal the reader thread instead of killing it with TerminateThread.
           TerminateThread cancels pending I/O with ERROR_OPERATION_ABORTED.
           SetEvent lets the thread notice via WaitForMultipleObjects, call
           CancelIo itself, and exit cleanly. */
        if (g_adapter.stop_event != NULL)
            SetEvent(g_adapter.stop_event);
        WaitForSingleObject(g_adapter.reader_thread, 3000);
        CloseHandle(g_adapter.reader_thread);
        g_adapter.reader_thread = NULL;
    }
    if (g_adapter.stop_event != NULL) {
        CloseHandle(g_adapter.stop_event);
        g_adapter.stop_event = NULL;
    }
    if (g_adapter.writer_sock != INVALID_SOCKET) {
        closesocket(g_adapter.writer_sock);
        g_adapter.writer_sock = INVALID_SOCKET;
    }
    if (g_adapter.reader_sock != INVALID_SOCKET) {
        closesocket(g_adapter.reader_sock);
        g_adapter.reader_sock = INVALID_SOCKET;
    }
    if (g_adapter.adapter_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_adapter.adapter_handle);
        g_adapter.adapter_handle = INVALID_HANDLE_VALUE;
    }
    return 0;
}

int tun_write(hans_fd_t fd, char *buf, int len)
{
    (void)fd;

    OVERLAPPED ov;
    DWORD written;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        set_error("tap write: CreateEvent: %s", winerr_str(GetLastError()));
        return -1;
    }

    /* Pass NULL for lpNumberOfBytesWritten — unreliable on overlapped handles. */
    if (!WriteFile(g_adapter.adapter_handle, buf, (DWORD)len, NULL, &ov)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            set_error("tap write: WriteFile: %s", winerr_str(err));
            CloseHandle(ov.hEvent);
            return -1;
        }
    }

    /* Always obtain the final byte count via GetOverlappedResult. */
    if (!GetOverlappedResult(g_adapter.adapter_handle, &ov, &written, TRUE)) {
        set_error("tap write: GetOverlappedResult: %s", winerr_str(GetLastError()));
        CloseHandle(ov.hEvent);
        return -1;
    }

    CloseHandle(ov.hEvent);
    return (int)written;
}

int tun_read(hans_fd_t fd, char *buf, int len)
{
    int n = recv((SOCKET)(uintptr_t)fd, buf, len, 0);
    if (n == SOCKET_ERROR) {
        set_error("tun_read: recv WSA %d", WSAGetLastError());
        return -1;
    }
    return n;
}

const char *tun_last_error(void)
{
    return s_error_buf;
}

bool tun_set_ip(hans_fd_t fd, uint32_t local, uint32_t network, uint32_t netmask)
{
    (void)fd;

    uint32_t   addresses[3];
    DWORD      status, len;
    OVERLAPPED ov;

    addresses[0] = htonl(local);
    addresses[1] = htonl(network);
    addresses[2] = htonl(netmask);

    /* The adapter handle was opened with FILE_FLAG_OVERLAPPED, so every
       I/O call — including DeviceIoControl — must supply an OVERLAPPED
       structure.  Passing NULL would be undefined behaviour per MSDN. */
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        set_error("tap set_ip: CreateEvent: %s", winerr_str(GetLastError()));
        return false;
    }

    if (!DeviceIoControl(g_adapter.adapter_handle,
                         TAP_WIN_IOCTL_CONFIG_TUN,
                         addresses, sizeof(addresses),
                         addresses, sizeof(addresses), NULL, &ov)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            set_error("configuring tap addresses: %s", winerr_str(err));
            CloseHandle(ov.hEvent);
            return false;
        }
    }
    if (!GetOverlappedResult(g_adapter.adapter_handle, &ov, &len, TRUE)) {
        set_error("configuring tap addresses: %s", winerr_str(GetLastError()));
        CloseHandle(ov.hEvent);
        return false;
    }

    ResetEvent(ov.hEvent);
    status = TRUE;
    if (!DeviceIoControl(g_adapter.adapter_handle,
                         TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status),
                         &status, sizeof(status), NULL, &ov)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            set_error("enabling tap device: %s", winerr_str(err));
            CloseHandle(ov.hEvent);
            return false;
        }
    }
    if (!GetOverlappedResult(g_adapter.adapter_handle, &ov, &len, TRUE)) {
        set_error("enabling tap device: %s", winerr_str(GetLastError()));
        CloseHandle(ov.hEvent);
        return false;
    }

    CloseHandle(ov.hEvent);

    /* Media status is now TRUE — safe to start reading from the adapter. */
    g_adapter.reader_thread = CreateThread(
        NULL, 0, reader_thread_proc, NULL, 0, NULL);
    if (g_adapter.reader_thread == NULL) {
        set_error("creating reader thread: %s", winerr_str(GetLastError()));
        return false;
    }

    clear_error();
    return true;
}

#endif /* _WIN32 */
