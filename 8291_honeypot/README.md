# Winbox Honeypot

This is a very simple implementation of the Winbox server. And by simple I mean: it accepts a single Winbox message, parses it, and always responds with a Winbox message indicating insufficient permissions. However! That's still enough to see some interesting stuff. In particular, when the incoming message is parsed, the program examines what the message is and where it would be routed. It is specifically interested in messages sent to mproxy handler #2 (since that is where CVE-2018-14847 is exploited).

Here is some sample output. For more see the sample directory:

```sh
albinolobster@ubuntu:~/routeros_internal/8291_honeypot/results$ cat 07012019.txt 
[+] 2019-7-1 10:53:54 | Loading GeoIP information from /var/lib/GeoIP/GeoLite2-City.mmdb
[+] 2019-7-1 10:53:54 | Using mmdb 1.3.2 and geolite2pp 0.0.1-2561
[+] 2019-7-1 12:23:49 | 216.250.101.133 | 45040 | New connection from Philippines
[!] 2019-7-1 12:23:49 | 216.250.101.133 | 45040 | CVE-2018-14847 attempt for: /////./..//////./..//////./../flash/rw/store/user.dat
[+] 2019-7-1 12:23:49 | 216.250.101.133 | 45040 | {bff0005:1,uff0006:5,uff0007:7,s1:'/////./..//////./..//////./../flash/rw/store/user.dat',Uff0001:[2,2],Uff0002:[0,8]}
[+] 2019-7-1 12:23:49 | Closing connection: 216.250.101.133:45040
[+] 2019-7-1 12:23:49 | 189.55.11.94 | 58313 | New connection from Brazil
[!] 2019-7-1 12:23:49 | 189.55.11.94 | 58313 | CVE-2018-14847 attempt for: /////./..//////./..//////./../flash/rw/store/user.dat
[+] 2019-7-1 12:23:49 | 189.55.11.94 | 58313 | {bff0005:1,uff0006:5,uff0007:7,s1:'/////./..//////./..//////./../flash/rw/store/user.dat',Uff0001:[2,2],Uff0002:[0,8]}
[+] 2019-7-1 12:23:49 | Closing connection: 189.55.11.94:58313
[+] 2019-7-1 12:23:50 | 194.99.104.22 | 50216 | New connection from Spain
[!] 2019-7-1 12:23:51 | 194.99.104.22 | 50216 | CVE-2018-14847 attempt for: /////./..//////./..//////./../flash/rw/store/user.dat
[+] 2019-7-1 12:23:51 | 194.99.104.22 | 50216 | {bff0005:1,uff0006:5,uff0007:7,s1:'/////./..//////./..//////./../flash/rw/store/user.dat',Uff0001:[2,2],Uff0002:[0,8]}
[+] 2019-7-1 12:23:51 | Closing connection: 194.99.104.22:50216
[+] 2019-7-1 14:22:52 | 201.148.126.202 | 54019 | New connection from Brazil
[+] 2019-7-1 14:22:52 | 202.142.146.67 | 56189 | New connection from Pakistan
[!] 2019-7-1 14:22:52 | 201.148.126.202 | 54019 | CVE-2018-14847 attempt for: /////./..//////./..//////./../flash/rw/store/user.dat
[+] 2019-7-1 14:22:52 | 201.148.126.202 | 54019 | {bff0005:1,uff0006:5,uff0007:7,s1:'/////./..//////./..//////./../flash/rw/store/user.dat',Uff0001:[2,2],Uff0002:[0,8]}
[+] 2019-7-1 14:22:52 | Closing connection: 201.148.126.202:54019
```

## What are the build dependencies?

This requires:

* boost 1.66 or higher
* libgeoip-dev
* [Geolite2++](https://www.ccoderun.ca/GeoLite2++/api/usage.html)
* [libmaxminddb](https://github.com/maxmind/libmaxminddb)
* cmake

## How do I build this jawn?

Just normal cmake. Try this:

```sh
mkdir build
cd build
cmake ..
make
```

Resolve dependencies as needed.

## Yo, you are looking for GeoLite2-City.mmdb in a weird location.

Ok. Go ahead and change it and recompile. ¯\\_(ツ)_/¯