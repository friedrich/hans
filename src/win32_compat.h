/*
 *  Hans - IP over ICMP
 *  Windows (MSVC) compatibility layer
 *
 *  Provides POSIX stubs and type definitions needed by the codebase
 *  when building with MSVC on Windows (including ARM64).
 *
 *  Include this header before any other project header in files
 *  that use POSIX APIs.
 */

#ifndef WIN32_COMPAT_H
#define WIN32_COMPAT_H

#ifdef _WIN32

/*
 * CRITICAL INCLUDE ORDER FOR MSVC
 * ================================
 * 1. <winsock2.h> must be first (before windows.h), and also provides
 *    struct timeval needed by src/time.h.
 * 2. <ctime> must come AFTER winsock2.h (so timeval is available) but
 *    BEFORE windows.h sets the _INC_TIME guard. Once _INC_TIME is set,
 *    <ctime> can no longer pull in time.h and its "using ::clock_t"
 *    declarations fail with "'clock_t' is not a member of global namespace".
 */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#  define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock2.h>   /* FIRST: defines struct timeval; must precede windows.h */
#include <ws2tcpip.h>

#ifdef __cplusplus
#  include <ctime>      /* BEFORE windows.h sets _INC_TIME guard */
#  include <cstdlib>
#  include <cstdio>
#  include <cstring>
#  include <cerrno>
#else
#  include <stdlib.h>
#  include <stdio.h>
#  include <string.h>
#  include <errno.h>
#endif

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <signal.h>

/* ------------------------------------------------------------------ */
/* Portable fd/socket type                                             */
/* SOCKET is UINT_PTR (64-bit on ARM64); intptr_t covers it safely.   */
/* INVALID_SOCKET (all-bits-set) maps to (intptr_t)-1, matching -1.   */
/* ------------------------------------------------------------------ */
typedef intptr_t hans_fd_t;

/* ------------------------------------------------------------------ */
/* POSIX uid / gid (not used on Windows — kept for API compatibility) */
/* ------------------------------------------------------------------ */
typedef int uid_t;
typedef int gid_t;

/* ------------------------------------------------------------------ */
/* IPv4 header — replaces <netinet/ip.h> / struct ip                  */
/* Layout matches the standard 20-byte IPv4 header.                   */
/* ------------------------------------------------------------------ */
#ifndef _STRUCT_IP_DEFINED
#define _STRUCT_IP_DEFINED
struct ip {
    uint8_t        ip_vhl;   /* version (4 bits) + IHL (4 bits) */
    uint8_t        ip_tos;   /* type of service                  */
    uint16_t       ip_len;   /* total length                     */
    uint16_t       ip_id;    /* identification                   */
    uint16_t       ip_off;   /* fragment offset field            */
    uint8_t        ip_ttl;   /* time to live                     */
    uint8_t        ip_p;     /* protocol                         */
    uint16_t       ip_sum;   /* checksum                         */
    struct in_addr ip_src;   /* source address                   */
    struct in_addr ip_dst;   /* destination address              */
}; /* 20 bytes */
#endif /* _STRUCT_IP_DEFINED */

/* ------------------------------------------------------------------ */
/* syslog                                                              */
/* ------------------------------------------------------------------ */
#define LOG_EMERG    0
#define LOG_ALERT    1
#define LOG_CRIT     2
#define LOG_ERR      3
#define LOG_WARNING  4
#define LOG_NOTICE   5
#define LOG_INFO     6
#define LOG_DEBUG    7

#define LOG_DAEMON   (3 << 3)
#define LOG_PERROR   0x20

/* LOG_UPTO: keep priorities <= x; simplified to identity on Windows */
#define LOG_UPTO(x)  (x)

#ifdef __cplusplus
extern "C" {
#endif

void hans_openlog(const char *ident, int option, int facility);
void hans_syslog(int priority, const char *format, ...);
void hans_closelog(void);
void hans_setlogmask(int mask);

#ifdef __cplusplus
}
#endif

#define openlog(id, opt, fac)  hans_openlog((id), (opt), (fac))
#define syslog                 hans_syslog
#define closelog()             hans_closelog()
#define setlogmask(m)          hans_setlogmask(m)

/* ------------------------------------------------------------------ */
/* gettimeofday                                                        */
/* struct timeval is provided by <winsock2.h>                         */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif
int hans_gettimeofday(struct timeval *tv, void *tz);
#ifdef __cplusplus
}
#endif

#define gettimeofday hans_gettimeofday

/* ------------------------------------------------------------------ */
/* getopt                                                              */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif

extern char *hans_optarg;
extern int   hans_optind;
extern int   hans_opterr;
extern int   hans_optopt;
int hans_getopt(int argc, char * const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif

#define getopt  hans_getopt
#define optarg  hans_optarg
#define optind  hans_optind
#define opterr  hans_opterr
#define optopt  hans_optopt

/* ------------------------------------------------------------------ */
/* daemon() — Windows has no background process fork mechanism.       */
/* Returns -1 so the caller stays in foreground mode.                 */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif
int hans_daemon(int nochdir, int noclose);
#ifdef __cplusplus
}
#endif

#define daemon hans_daemon

/* ------------------------------------------------------------------ */
/* Winsock initialisation / cleanup                                    */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif
void hans_winsock_init(void);
void hans_winsock_cleanup(void);

/* TCP loopback socket-pair (replacement for UNIX socketpair)         */
int win32_socketpair(SOCKET sv[2]);
#ifdef __cplusplus
}
#endif

/* ------------------------------------------------------------------ */
/* close() on sockets: Winsock requires closesocket()                 */
/* Use this inline wrapper where socket fds are closed.               */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C"
#endif
static __inline int hans_close_socket(hans_fd_t fd)
{
    return closesocket((SOCKET)(uintptr_t)fd);
}

#else /* !_WIN32 */

/* On POSIX, hans_fd_t is just int */
typedef int hans_fd_t;

#endif /* _WIN32 */
#endif /* WIN32_COMPAT_H */
