/*
 *  Hans - IP over ICMP
 *  Windows (MSVC) compatibility implementation
 */

#ifdef _WIN32

#include "win32_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/* syslog                                                              */
/* ================================================================== */

static const char *s_ident    = "hans";
static int         s_logmask  = 0xFF;   /* all priorities enabled */

void hans_openlog(const char *ident, int /*option*/, int /*facility*/)
{
    if (ident && *ident)
        s_ident = ident;
}

void hans_syslog(int priority, const char *format, ...)
{
    if (priority > s_logmask)
        return;

    const char *level;
    switch (priority) {
        case LOG_EMERG:   level = "EMERG";   break;
        case LOG_ALERT:   level = "ALERT";   break;
        case LOG_CRIT:    level = "CRIT";    break;
        case LOG_ERR:     level = "ERROR";   break;
        case LOG_WARNING: level = "WARNING"; break;
        case LOG_NOTICE:  level = "NOTICE";  break;
        case LOG_INFO:    level = "INFO";    break;
        case LOG_DEBUG:   level = "DEBUG";   break;
        default:          level = "?";       break;
    }

    va_list ap;
    va_start(ap, format);
    fprintf(stderr, "[%s] %s: ", s_ident, level);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void hans_closelog(void) { }

void hans_setlogmask(int mask)
{
    s_logmask = mask;
}

/* ================================================================== */
/* gettimeofday                                                        */
/* Uses GetSystemTimeAsFileTime for ~100 ns precision.                */
/* ================================================================== */

int hans_gettimeofday(struct timeval *tv, void * /*tz*/)
{
    /* Windows FILETIME: 100-ns intervals since 1601-01-01.
       Unix epoch offset (1601-01-01 → 1970-01-01): 11644473600 seconds
       = 116444736000000000 × 100 ns intervals */
    static const ULONGLONG EPOCH = 116444736000000000ULL;

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULONGLONG t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= EPOCH;

    tv->tv_sec  = (long)(t / 10000000ULL);
    tv->tv_usec = (long)((t % 10000000ULL) / 10ULL);
    return 0;
}

/* ================================================================== */
/* getopt                                                              */
/* Simple POSIX-compatible getopt() implementation.                   */
/* ================================================================== */

char *hans_optarg = NULL;
int   hans_optind = 1;
int   hans_opterr = 1;
int   hans_optopt = 0;

int hans_getopt(int argc, char * const argv[], const char *optstring)
{
    static int sp = 1;
    int c;
    const char *cp;

    if (sp == 1) {
        if (hans_optind >= argc ||
            argv[hans_optind][0] != '-' ||
            argv[hans_optind][1] == '\0')
            return -1;
        if (strcmp(argv[hans_optind], "--") == 0) {
            hans_optind++;
            return -1;
        }
    }

    hans_optopt = c = (unsigned char)argv[hans_optind][sp];

    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (hans_opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[hans_optind][++sp] == '\0') {
            hans_optind++;
            sp = 1;
        }
        return '?';
    }

    if (*++cp == ':') {
        if (argv[hans_optind][sp + 1] != '\0') {
            hans_optarg = &argv[hans_optind++][sp + 1];
        } else if (++hans_optind >= argc) {
            if (hans_opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n",
                        argv[0], c);
            sp = 1;
            return '?';
        } else {
            hans_optarg = argv[hans_optind++];
        }
        sp = 1;
    } else {
        if (argv[hans_optind][++sp] == '\0') {
            sp = 1;
            hans_optind++;
        }
        hans_optarg = NULL;
    }

    return c;
}

/* ================================================================== */
/* daemon() stub                                                       */
/* Windows does not support Unix-style daemonisation. Return -1 so   */
/* the caller (main.cpp) stays in foreground mode.                    */
/* ================================================================== */

int hans_daemon(int /*nochdir*/, int /*noclose*/)
{
    return -1;
}

/* ================================================================== */
/* Winsock init / cleanup                                              */
/* ================================================================== */

void hans_winsock_init(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        exit(1);
    }
}

void hans_winsock_cleanup(void)
{
    WSACleanup();
}

/* ================================================================== */
/* win32_socketpair — TCP loopback pair                               */
/*                                                                     */
/* Creates two connected TCP sockets via 127.0.0.1 so that both ends  */
/* can be used with select() (unlike anonymous pipes).                */
/* sv[0] = "read" end (main code),  sv[1] = "write" end (thread).    */
/* ================================================================== */

int win32_socketpair(SOCKET sv[2])
{
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    DWORD last_err = 0;

    sv[0] = sv[1] = INVALID_SOCKET;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET)
        goto fail;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* OS picks a free port */

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;
    if (getsockname(listen_sock, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
        goto fail;
    if (listen(listen_sock, 1) == SOCKET_ERROR)
        goto fail;

    sv[0] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sv[0] == INVALID_SOCKET)
        goto fail;

    if (connect(sv[0], (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;

    sv[1] = accept(listen_sock, NULL, NULL);
    if (sv[1] == INVALID_SOCKET)
        goto fail;

    closesocket(listen_sock);

    /* Disable Nagle algorithm for low latency */
    {
        BOOL nodelay = TRUE;
        setsockopt(sv[0], IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
        setsockopt(sv[1], IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
    }

    return 0;

fail:
    last_err = WSAGetLastError();
    if (listen_sock != INVALID_SOCKET) closesocket(listen_sock);
    if (sv[0] != INVALID_SOCKET) { closesocket(sv[0]); sv[0] = INVALID_SOCKET; }
    if (sv[1] != INVALID_SOCKET) { closesocket(sv[1]); sv[1] = INVALID_SOCKET; }
    WSASetLastError(last_err);
    return -1;
}

#endif /* _WIN32 */
