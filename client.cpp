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

#include "client.h"
#include "server.h"
#include "exception.h"
#include "config.h"

#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>

using namespace std;

const Worker::TunnelHeader::Magic Client::magic("9967");

Client::Client(int tunnelMtu, const char *deviceName, uint32_t serverIp, int maxPolls, const char *passphrase, uid_t uid, gid_t gid)
	: Worker(tunnelMtu, deviceName, false, uid, gid), auth(passphrase)
{
	this->serverIp = serverIp;
	this->maxPolls = maxPolls;

	state = STATE_CLOSED;
}

Client::~Client()
{
	
}

void Client::sendConnectionRequest()
{
	Server::ClientConnectData *connectData = (Server::ClientConnectData *)payloadBuffer();
	connectData->maxPolls = maxPolls;

	syslog(LOG_DEBUG, "sending connection request");

	sendEchoToServer(TunnelHeader::TYPE_CONNECTION_REQUEST, sizeof(Server::ClientConnectData));

	state = STATE_CONNECTION_REQUEST_SENT;
	setTimeout(5000);
}

void Client::sendChallengeResponse(int dataLength)
{
	if (dataLength != CHALLENGE_SIZE)
		throw Exception("invalid challenge received");

	state = STATE_CHALLENGE_RESPONSE_SENT;

	syslog(LOG_DEBUG, "sending challenge response");

	vector<char> challenge;
	challenge.resize(dataLength);
	memcpy(&challenge[0], payloadBuffer(), dataLength);

	Auth::Response response = auth.getResponse(challenge);

	memcpy(payloadBuffer(), (char *)&response, sizeof(Auth::Response));
	sendEchoToServer(TunnelHeader::TYPE_CHALLENGE_RESPONSE, sizeof(Auth::Response));

	setTimeout(5000);
}

bool Client::handleEchoData(const TunnelHeader &header, int dataLength, uint32_t realIp, bool reply, int id, int seq)
{
	if (realIp != serverIp || !reply)
		return false;

	if (header.magic != Server::magic)
		return false;

	switch (header.type)
	{
		case TunnelHeader::TYPE_RESET_CONNECTION:
			syslog(LOG_DEBUG, "reset reveiced");
			sendConnectionRequest();
			return true;
		case TunnelHeader::TYPE_SERVER_FULL:
			if (state == STATE_CONNECTION_REQUEST_SENT)
			{
				throw Exception("server full");
			}
			break;
		case TunnelHeader::TYPE_CHALLENGE:
			if (state == STATE_CONNECTION_REQUEST_SENT)
			{
				syslog(LOG_DEBUG, "challenge received");
				sendChallengeResponse(dataLength);
				return true;
			}
			break;
		case TunnelHeader::TYPE_CONNECTION_ACCEPT:
			if (state == STATE_CHALLENGE_RESPONSE_SENT)
			{
				if (dataLength != sizeof(uint32_t))
				{
					throw Exception("invalid ip received");
					return true;
				}

				syslog(LOG_INFO, "connection established");

				tun->setIp(ntohl(*(uint32_t *)payloadBuffer()));
				state = STATE_ESTABLISHED;

				dropPrivileges();
				startPolling();

				return true;
			}
			break;
		case TunnelHeader::TYPE_CHALLENGE_ERROR:
			if (state == STATE_CHALLENGE_RESPONSE_SENT)
			{
				throw Exception("password error");
			}
			break;
		case TunnelHeader::TYPE_DATA:
			if (state == STATE_ESTABLISHED)
			{
				handleDataFromServer(dataLength);
				return true;
			}
			break;
	}

	syslog(LOG_DEBUG, "invalid packet type: %d, state:\n", header.type, state);

	return true;
}

void Client::sendEchoToServer(int type, int dataLength)
{
	if (maxPolls == 0 && state == STATE_ESTABLISHED)
		setTimeout(KEEP_ALIVE_INTERVAL);

	sendEcho(magic, type, dataLength, serverIp, false, ICMP_ID, 0);
}

void Client::startPolling()
{
	if (maxPolls == 0)
	{
		setTimeout(KEEP_ALIVE_INTERVAL);
	}
	else
	{
		for (int i = 0; i < maxPolls; i++)
			sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
		setTimeout(POLL_INTERVAL);
	}
}

void Client::handleDataFromServer(int dataLength)
{
	sendToTun(dataLength);

	if (maxPolls != 0)
		sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
}

void Client::handleTunData(int dataLength, uint32_t sourceIp, uint32_t destIp)
{
	if (state != STATE_ESTABLISHED)
		return;

	sendEchoToServer(TunnelHeader::TYPE_DATA, dataLength);
}

void Client::handleTimeout()
{
	switch (state)
	{
		case STATE_CONNECTION_REQUEST_SENT:
		case STATE_CHALLENGE_RESPONSE_SENT:
			sendConnectionRequest();
			break;

		case STATE_ESTABLISHED:
			sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
			setTimeout(maxPolls == 0 ? KEEP_ALIVE_INTERVAL : POLL_INTERVAL);
			break;
		case STATE_CLOSED:
			break;
	}
}

void Client::run()
{
	now = Time::now();

	sendConnectionRequest();

	Worker::run();
}
