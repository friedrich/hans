/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <friedrich.schoeller@gmail.com>
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
#include <list>

class Server : public Worker
{
public:
	Server(int tunnelMtu, const char *deviceName, const char *passphrase, uint32_t network, bool answerEcho, uid_t uid, gid_t gid, int pollTimeout);
	virtual ~Server();

	struct ClientConnectData
	{
		uint8_t maxPolls;
	};

	static const Worker::TunnelHeader::Magic magic;

protected:
	struct Packet
	{
		int type;
		std::vector<char> data;
	};

	struct ClientData
	{
		enum State
		{
			STATE_NEW,
			STATE_CHALLENGE_SENT,
			STATE_ESTABLISHED
		};

		uint32_t realIp;
		uint32_t tunnelIp;

		std::queue<Packet> pendingPackets;

		int maxPolls;
		std::queue<Time> pollTimes;
		Time lastActivity;

		State state;

		Auth::Challenge challenge;
	};

	typedef std::vector<ClientData> ClientList;
	typedef std::map<uint32_t, int> ClientIpMap;

	virtual bool handleEchoData(const TunnelHeader &header, int dataLength, uint32_t realIp, bool reply, int id, int seq);
	virtual void handleTunData(int dataLength, uint32_t sourceIp, uint32_t destIp);
	virtual void handleTimeout();

	virtual void run();

	void serveTun(ClientData *client);

	void handleUnknownClient(const TunnelHeader &header, int dataLength, uint32_t realIp);
	void removeClient(ClientData *client);

	void sendChallenge(ClientData *client);
	void checkChallenge(ClientData *client, int dataLength);
	void sendReset(ClientData *client);

	void sendEchoToClient(ClientData *client, int type, int dataLength);

	void pollReceived(ClientData *client);

	uint32_t reserveTunnelIp();
	void releaseTunnelIp(uint32_t tunnelIp);

	ClientData *getClientByTunnelIp(uint32_t ip);
	ClientData *getClientByRealIp(uint32_t ip);

	Auth auth;

	uint32_t network;
	std::list<uint32_t> usedIps;

	Time pollTimeout;

	ClientList clientList;
	ClientIpMap clientRealIpMap;
	ClientIpMap clientTunnelIpMap;
};

#endif
