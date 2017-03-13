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

#include "client.h"
#include "server.h"
#include "exception.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>
#include <netdb.h>
// #include <uuid/uuid.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>

static Worker *worker = NULL;

static void sig_term_handler(int)
{
    syslog(LOG_INFO, "SIGTERM received");
    if (worker)
        worker->stop();
}

static void sig_int_handler(int)
{
    syslog(LOG_INFO, "SIGINT received");
    if (worker)
        worker->stop();
}

static void usage()
{
    printf(
        "Hans - IP over ICMP version 1.0\n\n"
        "RUN AS SERVER\n"
        "  hans -s network [-46fvr] [-p password] [-u unprivileged_user] [-d tun_device] [-m reference_mtu] [-a ip]\n\n"
        "RUN AS CLIENT\n"
        "  hans -c server  [-46fv]  [-p password] [-u unprivileged_user] [-d tun_device] [-m reference_mtu] [-w polls]\n\n"
        "ARGUMENTS\n"
        "  -s network    Run as a server with the given network address for the virtual interface. Linux only!\n"
        "  -c server     Connect to a server.\n"
        "  -4            Use IPv4 ICMP only.\n"
        "  -6            Use IPv6 ICMPv6 only.\n"
        "  -f            Run in foreground.\n"
        "  -v            Print debug information.\n"
        "  -r            Respond to ordinary pings. Only in server mode.\n"
        "  -p password   Use a password.\n"
        "  -u username   Set the user under which the program should run.\n"
        "  -d device     Use the given tun device.\n"
        "  -m mtu        Use this mtu to calculate the tunnel mtu.\n"
        "                The generated echo packets will not be bigger than this value.\n"
        "                Has to be the same on client and server. Defaults to 1500.\n"
        "  -w polls      Number of echo requests the client sends to the server for polling.\n"
        "                0 disables polling. Defaults to 10.\n"
        "  -I            Identify clients by ip + echo id.\n"
        "  -i            Change the echo id for every echo request.\n"
        "  -q            Change the echo sequence number for every echo request.\n"
        "  -a ip         Try to get assigned the given tunnel ip address.\n"
    );
}

int main(int argc, char *argv[])
{
    const char *serverName;
    const char *userName = NULL;
    const char *password = "";
    const char *device = NULL;
    bool ipv4 = false;
    bool ipv6 = false;
    bool isServer = false;
    bool isClient = false;
    bool foreground = false;
    int mtu = 1500;
    int maxPolls = 10;
    uint32_t network = INADDR_NONE;
    uint32_t clientIp = INADDR_NONE;
    bool answerPing = false;
    uid_t uid = 0;
    gid_t gid = 0;
    bool trackEchoId = false;
    bool changeEchoId = false;
    bool changeEchoSeq = false;
    bool verbose = false;

    openlog(argv[0], LOG_PERROR, LOG_DAEMON);

    int c;
    while ((c = getopt(argc, argv, "46fru:d:p:s:c:m:w:qIiva:")) != -1)
    {
        switch(c) {
            case '4':
                ipv4 = true;
                break;
            case '6':
                ipv6 = true;
                break;
            case 'f':
                foreground = true;
                break;
            case 'u':
                userName = optarg;
                break;
            case 'd':
                device = optarg;
                break;
            case 'p':
                password = strdup(optarg);
                memset(optarg, 0, strlen(optarg));
                break;
            case 'c':
                isClient = true;
                serverName = optarg;
                break;
            case 's':
                isServer = true;
                network = ntohl(inet_addr(optarg));
                if (network == INADDR_NONE)
                    printf("invalid network\n");
                break;
            case 'm':
                mtu = atoi(optarg);
                break;
            case 'w':
                maxPolls = atoi(optarg);
                break;
            case 'r':
                answerPing = true;
                break;
            case 'q':
                changeEchoSeq = true;
                break;
            case 'I':
                trackEchoId = true;
                break;
            case 'i':
                changeEchoId = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'a':
                clientIp = ntohl(inet_addr(optarg));
                break;
            default:
                usage();
                return 1;
        }
    }

    mtu -= Echo::headerSize() + Worker::headerSize();

    if (mtu < 68)
    {
        // RFC 791: Every internet module must be able to forward a datagram of 68 octets without further fragmentation.
        printf("mtu too small\n");
        return 1;
    }

    if (!ipv4 && !ipv6) {
        ipv4 = true;
        ipv6 = true;
    }

    if ((isClient == isServer) ||
        (isServer && network == INADDR_NONE) ||
        (maxPolls < 0 || maxPolls > 255) ||
        (isServer && (changeEchoSeq || changeEchoId)))
    {
        usage();
        return 1;
    }

    if (userName != NULL)
    {
#ifdef WIN32
        syslog(LOG_ERR, "dropping privileges is not supported on Windows");
        return 1;
#endif
        passwd *pw = getpwnam(userName);

        if (pw != NULL)
        {
            uid = pw->pw_uid;
            gid = pw->pw_gid;
        }
        else
        {
            syslog(LOG_ERR, "user not found");
            return 1;
        }
    }

    if (!verbose)
        setlogmask(LOG_UPTO(LOG_INFO));

    signal(SIGTERM, sig_term_handler);
    signal(SIGINT, sig_int_handler);

    try
    {
        if (isServer)
        {
            worker = new Server(mtu, device, password, network, answerPing, trackEchoId, uid, gid, 5000, ipv4, ipv6);
        }
        else
        {
            in6_addr_union serverIp = { 0 };
            struct addrinfo proto = { 0 };
            struct addrinfo* ainfo;

            if (ipv4 && !ipv6) proto.ai_family = AF_INET;
            else if (!ipv4 && ipv6) proto.ai_family = AF_INET6;
            else if (ipv4 && ipv6) proto.ai_family = AF_UNSPEC;
            int ai = getaddrinfo(serverName, NULL, &proto, &ainfo);

            if (ai)
            {
                syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(ai));
                return 1;
            }

            if (ainfo->ai_family == AF_INET) {
                serverIp.in6_addr_union_32[0] = 0;
                serverIp.in6_addr_union_32[1] = 0;
                serverIp.in6_addr_union_16[4] = 0;
                serverIp.in6_addr_union_16[5] = 0xffff;
                serverIp.in6_addr_union_32[3] = ((sockaddr_in*)(ainfo->ai_addr))->sin_addr.s_addr;
            } else
                serverIp.in6_addr_union_128 = ((sockaddr_in6*)(ainfo->ai_addr))->sin6_addr;

            worker = new Client(mtu, device, serverIp, maxPolls, password, uid, gid, trackEchoId, changeEchoId, changeEchoSeq, clientIp, ipv6 && (ainfo->ai_family == AF_INET6));

            freeaddrinfo(ainfo);
        }

        if (!foreground)
        {
            syslog(LOG_INFO, "detaching from terminal");
            daemon(0, 0);
        }

        worker->run();
    }
    catch (Exception e)
    {
        syslog(LOG_ERR, "%s", e.errorMessage());
        delete worker;
        return 1;
    }

    return 0;
}
