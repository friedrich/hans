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

#include <iostream>
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
#include <memory>

#ifndef AI_V4MAPPED // Not supported on OpenBSD 6.0
#define AI_V4MAPPED 0
#endif

using std::string;

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
    std::cerr <<
        "Hans - IP over ICMP version 1.1\n\n"
        "RUN AS CLIENT\n"
        "  hans -c server [-fv] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [-w polls]\n\n"
        "RUN AS SERVER (linux only)\n"
        "  hans -s network [-fvr] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [-a ip]\n\n"
        "ARGUMENTS\n"
        "  -c server     Run as client. Connect to given server address.\n"
        "  -s network    Run as server. Use given network address on virtual interfaces.\n"
        "  -p passphrase Set passphrase.\n"
        "  -u username   Change user under which the program runs.\n"
        "  -a ip         Request assignment of given tunnel ip address from the server.\n"
        "  -r            Respond to ordinary pings in server mode.\n"
        "  -d device     Use given tun device.\n"
        "  -m mtu        Set maximum echo packet size. This should correspond to the MTU\n"
        "                of the network between client and server, which is usually 1500\n"
        "                over Ethernet. Has to be the same on client and server. Defaults\n"
        "                to 1500.\n"
        "  -w polls      Number of echo requests the client sends in advance for the\n"
        "                server to reply to. 0 disables polling, which is the best choice\n"
        "                if the network allows unlimited echo replies. Defaults to 10.\n"
        "  -i            Change echo id on every echo request. May help with buggy\n"
        "                routers. May impact performance with others.\n"
        "  -q            Change echo sequence number on every echo request. May help with\n"
        "                buggy routers. May impact performance with others.\n"
        "  -f            Run in foreground.\n"
        "  -v            Print debug information.\n";
}

int main(int argc, char *argv[])
{
    string serverName;
    string userName;
    string passphrase;
    string device;
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
    bool changeEchoId = false;
    bool changeEchoSeq = false;
    bool verbose = false;

    openlog(argv[0], LOG_PERROR, LOG_DAEMON);

    int c;
    while ((c = getopt(argc, argv, "fru:d:p:s:c:m:w:qiva:")) != -1)
    {
        switch(c) {
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
                passphrase = optarg;
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
                    std::cerr << "invalid network\n";
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
        // RFC 791: Every internet module must be able to forward a datagram of
        // 68 octets without further fragmentation.
        std::cerr << "mtu too small\n";
        return 1;
    }

    if ((isClient == isServer) ||
        (isServer && network == INADDR_NONE) ||
        (maxPolls < 0 || maxPolls > 255) ||
        (isServer && (changeEchoSeq || changeEchoId)))
    {
        usage();
        return 1;
    }

    if (!userName.empty())
    {
#ifdef WIN32
        syslog(LOG_ERR, "dropping privileges is not supported on Windows");
        return 1;
#endif
        passwd *pw = getpwnam(userName.data());

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
            worker = new Server(mtu, device.empty() ? NULL : &device, passphrase,
                                network, answerPing, uid, gid, 5000);
        }
        else
        {
            struct addrinfo hints = {0};
            struct addrinfo *res = NULL;

            hints.ai_family = AF_INET;
            hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

            int err = getaddrinfo(serverName.data(), NULL, &hints, &res);
            if (err)
            {
                syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(err));
                return 1;
            }

            sockaddr_in *sockaddr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
            uint32_t serverIp = sockaddr->sin_addr.s_addr;

            worker = new Client(mtu, device.empty() ? NULL : &device,
                                ntohl(serverIp), maxPolls, passphrase, uid, gid,
                                changeEchoId, changeEchoSeq, clientIp);

            freeaddrinfo(res);
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
        syslog(LOG_ERR, "%s", e.errorMessage().data());
        delete worker;
        return 1;
    }

    return 0;
}
