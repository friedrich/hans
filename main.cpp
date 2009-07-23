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

#include <stdio.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

void usage()
{
	printf(
		"Hans - IP over ICMP version 0.1 dev\n\n"
		"RUN AS SERVER\n"
		"  hans -s network [-fr] [-p password] [-u unprivileged_user] [-d tun_device] [-m reference_mtu]\n\n"
		"RUN AS CLIENT\n"
		"  hans -c server  [-f]  [-p password] [-u unprivileged_user] [-d tun_device] [-m reference_mtu] [-w polls]\n\n"
		"ARGUMENTS\n"
		"  -s network    Run as a server with the given network address for the virtual interface.\n"
		"  -c server     Connect to a server.\n"
		"  -f            Run in foreground.\n"
		"  -r            Respond to ordinary pings. Only in server mode.\n"
		"                Use this when you disable echo replies of your operating system, which is a good idea.\n"
		"  -p password   Use a password.\n"
		"  -u username   Set the user under which the program should run.\n"
		"  -d device     Use the given tun device.\n"
		"  -m mtu        Use this mtu to calculate the tunnel mtu.\n"
		"                The generated ICMP packets will not be bigger than this value.\n"
		"                Has to be the same on client and server.\n"
		"                In most cases you don't want to set this. Defaults to 1500.\n"
		"  -w polls      Number of echo requests the client sends to the server for polling.\n"
		"                If your network allows unlimited echo replies set this to 0 to disable polling.\n"
		"                The default value of 10 is regarded as pretty high.\n"
		"                Set this to a lower value if you experience packet loss through the tunnel.\n"
		"                Set this to 1 in extreme cases, when your network allows only one echo reply per request.\n"
		"                A low value will decrease the performance of the tunnel.\n");
}

int main(int argc, char *argv[])
{
	const char *serverName;
	const char *userName = NULL;
	const char *password = "";
	const char *device = NULL;
	bool isServer = false;
	bool isClient = false;
	bool foreground = false;
	int mtu = 1500;
	int maxPolls = 10;
	uint32_t network = INADDR_NONE;
	bool answerPing = false;
	uid_t uid = 0;
	gid_t gid = 0;

	openlog(argv[0], LOG_PERROR, LOG_DAEMON);

	int c;
	while ((c = getopt(argc, argv, "fru:d:p:s:c:m:w:")) != -1)
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

	if ((isClient == isServer) ||
		(isServer && network == INADDR_NONE) ||
		(maxPolls < 0 || maxPolls > 255))
	{
		usage();
		return 1;
	}

	if (userName != NULL)
	{
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

	try
	{
		Worker *worker;

		if (isServer)
		{
			worker = new Server(mtu, device, password, network, answerPing, uid, gid, 5000);
		}
		else
		{
			uint32_t serverIp = inet_addr(serverName);
			if (serverIp == INADDR_NONE)
			{
				struct hostent* he = gethostbyname(serverName);
				if (!he)
				{
					syslog(LOG_ERR, "gethostbyname: %s", hstrerror(h_errno));
					return 1;
				}

				serverIp = *(uint32_t *)he->h_addr;
			}

			worker = new Client(mtu, device, ntohl(serverIp), maxPolls, password, uid, gid);
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
		return 1;
	}

    return 0;
}
