#!/data/data/com.termux/files/usr/bin/bash

hans="/data/data/com.termux/files/home/hans/hans"

$hans -c 172.16.0.1 -p change_this_password -v
ip rule add from all lookup main pref 1
bash -c "trap 'exit 0' INT; logcat -v color | grep $hans"
killall $hans
ip rule del from all lookup main pref 1