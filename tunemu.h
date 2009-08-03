/*
 *  tunemu - Tun device emulation for Darwin
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

#ifndef TUN_EMU_H
#define TUN_EMU_H

typedef char tun_emu_device[7];

extern char tun_emu_error[];

int tun_emu_open(tun_emu_device dev);
int tun_emu_close(int fd);
int tun_emu_read(int fd, char *buffer, int length);
int tun_emu_write(int fd, char *buffer, int length);

#endif
