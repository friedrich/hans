Hans - IP over ICMP
===================

Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could call it a ping tunnel. This can be useful when you find yourself in the situation that your Internet access is firewalled, but pings are allowed.

http://code.gerade.org/hans/

This repo adds the minimal necessary code changes for the code to be able to compile inside a [Termux](https://github.com/termux/termux-app) Android environment (inside the own device!).

Building and running instructions:
* For manipulating ICMP packets you need a rooted device.
* Install [Termux app](https://github.com/termux/termux-app), and then install the clang compiler and make: `pkg install clang make`
* Clone this repo and then you should be able to compile a binary from within your device with `make`
* Adapt and exec the hans_android.sh script (as root!) inside the repo, in my experience the "main" routing table needs to be added to `ip rule` for the Hans tunnel packets to be routed correctly. Also the binary outputs to logcat, this is handled in the script as well (good for debugging).
* These changes have not been tested with multiple devices or Android versions, it has been tested with an Android 10 device. If you encounter problems you'll possibly need to debug them with strace or ltrace.
* Systemd example service unit file and conf file are included as convenience.

Refs:
* https://github.com/friedrich/hans
* http://code.gerade.org/hans/
* https://github.com/raidenii/hans-android
* https://nethack.ch/2016/12/10/how-to-use-openvpn-over-an-ip-over-icmp-tunnel-hans/
* https://hundeboll.net/internet-tunneling-through-icmp.html

Happy ICMP tunneling ;)
