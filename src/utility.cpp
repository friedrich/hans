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

#include "utility.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

using namespace std;

string Utility::formatIp(const in6_addr_union& ip)
{
    if (ip.in6_addr_union_32[0] == 0 && ip.in6_addr_union_32[1] == 0 && ip.in6_addr_union_16[4] == 0 && ip.in6_addr_union_16[5] == 0xffff)
        return formatIp(ntohl(ip.in6_addr_union_32[3]));
    char buffer[40];
    sprintf(buffer, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip.in6_addr_union_8[0],ip.in6_addr_union_8[1],ip.in6_addr_union_8[2],ip.in6_addr_union_8[3],ip.in6_addr_union_8[4],ip.in6_addr_union_8[5],ip.in6_addr_union_8[6],ip.in6_addr_union_8[7],ip.in6_addr_union_8[8],ip.in6_addr_union_8[9],ip.in6_addr_union_8[10],ip.in6_addr_union_8[11],ip.in6_addr_union_8[12],ip.in6_addr_union_8[13],ip.in6_addr_union_8[14],ip.in6_addr_union_8[15]);
    return buffer;
}

string Utility::formatIp(uint32_t ip)
{
    char buffer[16];
    sprintf(buffer, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
    return buffer;
}

int Utility::rand()
{
    static bool init = false;
    if (!init)
    {
        init = true;
        srand(time(NULL));
    }
    return ::rand();
}
