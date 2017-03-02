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

#ifndef UTILITY_H
#define UTILITY_H

#include <netinet/in.h>
#include <string>
#include <stdint.h>

union in6_addr_union
{
    uint8_t  in6_addr_union_8[16];
    uint16_t in6_addr_union_16[8];
    uint32_t in6_addr_union_32[4];
    in6_addr in6_addr_union_128;
};

class Utility
{
public:
    static std::string formatIp(const in6_addr_union& ip);
    static std::string formatIp(uint32_t ip);
    static int rand();
};

#endif
