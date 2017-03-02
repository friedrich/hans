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

#include "worker.h"
#include "tun.h"
#include "exception.h"
#include "config.h"

#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <grp.h>

using namespace std;

Worker::TunnelHeader::Magic::Magic(const char *magic)
{
    memset(data, 0, sizeof(data));
    strncpy(data, magic, sizeof(data));
}

bool Worker::TunnelHeader::Magic::operator==(const Magic &other) const
{
    return memcmp(data, other.data, sizeof(data)) == 0;
}

bool Worker::TunnelHeader::Magic::operator!=(const Magic &other) const
{
    return memcmp(data, other.data, sizeof(data)) != 0;
}

Worker::Worker(int tunnelMtu, const char *deviceName, bool answerEcho, uid_t uid, gid_t gid, bool ICMP, bool ICMPv6)
{
    this->tunnelMtu = tunnelMtu;
    this->answerEcho = answerEcho;
    this->uid = uid;
    this->gid = gid;
    this->privilegesDropped = false;

    echo[0] = NULL;
    echo[1] = NULL;
    tun = NULL;

    try
    {
        if (ICMP)   echo[0] = new Echo(tunnelMtu + sizeof(TunnelHeader), false);
        if (ICMPv6) echo[1] = new Echo(tunnelMtu + sizeof(TunnelHeader), true);
        tun = new Tun(deviceName, tunnelMtu);
    }
    catch (...)
    {
        delete echo[0];
        delete echo[1];
        delete tun;

        throw;
    }
}

Worker::~Worker()
{
    delete echo[0];
    delete echo[1];
    delete tun;
}

void Worker::sendEcho(Echo* echo, const TunnelHeader::Magic &magic, int type, int length, const in6_addr_union& realIp, bool reply, uint16_t id, uint16_t seq)
{
    if (length > payloadBufferSize())
        throw Exception("packet too big");

    TunnelHeader *header = (TunnelHeader *)echo->sendPayloadBuffer();
    header->magic = magic;
    header->type = type;

    DEBUG_ONLY(printf("sending: type %d, length %d, id %d, seq %d\n", type, length, id, seq));

    echo->send(length + sizeof(TunnelHeader), realIp, reply, id, seq);
}

void Worker::sendToTun(Echo* echo, int length)
{
    tun->write(echoReceivePayloadBuffer(echo), length);
}

void Worker::setTimeout(Time delta)
{
    nextTimeout = now + delta;
}

void Worker::run()
{
    now = Time::now();
    alive = true;

    int maxFd = tun->getFd();
    if (echo[0] && ( echo[0]->getFd() > maxFd )) maxFd = echo[0]->getFd();
    if (echo[1] && ( echo[1]->getFd() > maxFd )) maxFd = echo[1]->getFd();

    while (alive)
    {
        fd_set fs;
        Time timeout;

        FD_ZERO(&fs);
        FD_SET(tun->getFd(), &fs);
        if (echo[0]) FD_SET(echo[0]->getFd(), &fs);
        if (echo[1]) FD_SET(echo[1]->getFd(), &fs);

        if (nextTimeout != Time::ZERO)
        {
            timeout = nextTimeout - now;
            if (timeout < Time::ZERO)
                timeout = Time::ZERO;
        }

        // wait for data or timeout
        int result = select(maxFd + 1 , &fs, NULL, NULL, nextTimeout != Time::ZERO ? &timeout.getTimeval() : NULL);
        if (result == -1)
        {
            if (alive)
                throw Exception("select", true);
            else
                return;
        }
        now = Time::now();

        // timeout
        if (result == 0)
        {
            nextTimeout = Time::ZERO;
            handleTimeout();
            continue;
        }

        // icmp data
        for (int e = 0 ; e < 2 ; ++e) if (echo[e] && FD_ISSET(echo[e]->getFd(), &fs))
        {
            bool reply;
            uint16_t id, seq;
            in6_addr_union ip;

            int dataLength = echo[e]->receive(ip, reply, id, seq);
            if (dataLength != -1)
            {
                bool valid = dataLength >= sizeof(TunnelHeader);

                if (valid)
                {
                    TunnelHeader *header = (TunnelHeader *)echo[e]->receivePayloadBuffer();

                    DEBUG_ONLY(printf("received: type %d, length %d, id %d, seq %d\n", header->type, dataLength - sizeof(TunnelHeader), id, seq));

                    valid = handleEchoData(echo[e], *header, dataLength - sizeof(TunnelHeader), ip, reply, id, seq);
                }

                if (!valid && !reply && answerEcho)
                {
                    memcpy(echo[e]->sendPayloadBuffer(), echo[e]->receivePayloadBuffer(), dataLength);
                    echo[e]->send(dataLength, ip, true, id, seq);
                }
            }
        }

        // data from tun
        if (FD_ISSET(tun->getFd(), &fs))
        {
            uint32_t sourceIp, destIp;
            int e = echo[0] ? 0 : 1;

            int dataLength = tun->read(echoSendPayloadBuffer(echo[e]), sourceIp, destIp);

            if (dataLength == 0)
                throw Exception("tunnel closed");

            if (echo[e ? 0 : 1])
                memcpy(echo[e ? 0 : 1]->sendPayloadBuffer(), echo[e ? 1 : 0]->sendPayloadBuffer(), dataLength + headerSize());

            if (dataLength != -1)
                handleTunData(dataLength, sourceIp, destIp);
        }
    }
}

void Worker::stop()
{
    alive = false;
}

void Worker::dropPrivileges()
{
    if (uid <= 0 || privilegesDropped)
        return;

#ifdef WIN32
    throw Exception("dropping privileges not supported");
#else
    syslog(LOG_INFO, "dropping privileges");

    if (setgroups(0, NULL) == -1)
        throw Exception("setgroups", true);

    if (setgid(gid) == -1)
        throw Exception("setgid", true);

    if (setuid(uid) == -1)
        throw Exception("setuid", true);

    privilegesDropped = true;
#endif
}
