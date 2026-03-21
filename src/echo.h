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

#ifndef ECHO_H
#define ECHO_H

#include <string>
#include <vector>
#include <stdint.h>

/* hans_fd_t: intptr_t on Windows (covers 64-bit SOCKET), int on POSIX */
#ifdef _WIN32
#  include "win32_compat.h"
#else
#  ifndef HANS_FD_T_DEFINED
#  define HANS_FD_T_DEFINED
   typedef int hans_fd_t;
#  endif
#endif

class Echo
{
public:
    Echo(int maxPayloadSize);
    ~Echo();

    hans_fd_t getFd() { return fd; }

    void send(int payloadLength, uint32_t realIp, bool reply, uint16_t id, uint16_t seq);
    int receive(uint32_t &realIp, bool &reply, uint16_t &id, uint16_t &seq);

    char *sendPayloadBuffer();
    char *receivePayloadBuffer();

    static int headerSize();
protected:
    struct EchoHeader
    {
        uint8_t type;
        uint8_t code;
        uint16_t chksum;
        uint16_t id;
        uint16_t seq;
    }; // size = 8

    uint16_t icmpChecksum(const char *data, int length);

    hans_fd_t fd;
    int bufferSize;
    std::vector<char> sendBuffer;
    std::vector<char> receiveBuffer;
};

#endif
