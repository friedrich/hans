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

#ifndef SERVER_H
#define SERVER_H

#include "worker.h"
#include "auth.h"

#include <map>
#include <queue>
#include <vector>
#include <set>
#include <list>

class Server : public Worker
{
public:
    Server(int tunnelMtu, const char *deviceName, const char *passphrase, uint32_t network, bool answerEcho, bool trackEchoId, uid_t uid, gid_t gid, int pollTimeout, bool ICMP = true, bool ICMPv6 = false);
    virtual ~Server();

    // change some time:
    // struct __attribute__ ((__packed__)) ClientConnectData
    struct ClientConnectData
    {
        uint8_t maxPolls;
        uint32_t desiredIp;
    };

    static const Worker::TunnelHeader::Magic magic;

protected:
    struct Packet
    {
        int type;
        std::vector<char> data;
    };

    struct in6_addr_echo_id
    {
        in6_addr_union addr;
        uint16_t id;
    };

    struct ClientData
    {
        enum State
        {
            STATE_NEW,
            STATE_CHALLENGE_SENT,
            STATE_ESTABLISHED
        };

        struct EchoId
        {
            EchoId(uint16_t id, uint16_t seq) { this->id = id; this->seq = seq; }

            uint16_t id;
            uint16_t seq;
        };

        Echo* echo;
        in6_addr_echo_id realIp;
        uint32_t tunnelIp;

        std::queue<Packet> pendingPackets;

        int maxPolls;
        std::queue<EchoId> pollIds;
        Time lastActivity;

        State state;

        Auth::Challenge challenge;
    };

    struct ClientIpMap_less {
        bool operator() (const in6_addr_echo_id& a, const in6_addr_echo_id& b) const {
            for (int i = 0 ; i < 4 ; ++i)
                if (a.addr.in6_addr_union_32[i] != b.addr.in6_addr_union_32[i])
                    return a.addr.in6_addr_union_32[i] < b.addr.in6_addr_union_32[i];
            return a.id < b.id;
        }
    };

    typedef std::list<ClientData> ClientList;
    typedef std::map<in6_addr_echo_id, ClientList::iterator, ClientIpMap_less> ClientIpMap;
    typedef std::map<uint32_t, ClientList::iterator> ClientTunMap;

    virtual bool handleEchoData(Echo* echo, const TunnelHeader &header, int dataLength, const in6_addr_union& realIp, bool reply, uint16_t id, uint16_t seq);
    virtual void handleTunData(int dataLength, uint32_t sourceIp, uint32_t destIp);
    virtual void handleTimeout();

    virtual void run();

    void serveTun(ClientData *client);

    void handleUnknownClient(Echo* echo, const TunnelHeader &header, int dataLength, const in6_addr_union& realIp, uint16_t echoId, uint16_t echoSeq);
    void removeClient(ClientData *client);

    void sendChallenge(ClientData *client);
    void checkChallenge(ClientData *client, int dataLength);
    void sendReset(ClientData *client);

    void sendEchoToClient(ClientData *client, int type, int dataLength);

    void pollReceived(ClientData *client, uint16_t echoId, uint16_t echoSeq);

    uint32_t reserveTunnelIp(uint32_t desiredIp);
    void releaseTunnelIp(uint32_t tunnelIp);

    ClientData *getClientByTunnelIp(uint32_t ip);
    ClientData *getClientByRealIp(const in6_addr_echo_id& ip);

    Auth auth;

    uint32_t network;
    std::set<uint32_t> usedIps;
    uint32_t latestAssignedIpOffset;

    Time pollTimeout;

    ClientList clientList;
    ClientIpMap clientRealIpMap;
    ClientTunMap clientTunnelIpMap;
};

#endif
