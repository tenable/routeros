# Winbox Scanner

This tool takes in a list of IP addresses and tries to send an unencrypted WinboxMessage request to port 8291 for the contents of the devices '/home/web/webfig/list' file. Depending on the version of RouterOS you'll get different responses:

* Before 6.28 - an error message
* 6.28 - 6.43rc - the length of the list file
* 6.43rc+ - a lie that the list file is zero bytes long

If we get the length of the file then we'll read it in and parse out the version. The 'list' file looks like this:

```
{ crc: 3443480142, size: 1276, name: "advtool.jg", unique: "advtool-b3bce0ff6230.jg", version: "6.45.2" },
{ crc: 2112313926, size: 3468, name: "dhcp.jg", unique: "dhcp-598b323ff954.jg", version: "6.45.2" },
{ crc: 4219737959, size: 4159, name: "hotspot.jg", unique: "hotspot-8a64fbf2a61a.jg", version: "6.45.2" },
{ crc: 1093970965, size: 22451, name: "icons.png", version: "6.45.2" },
{ crc: 1021519038, size: 3628, name: "mpls.jg", unique: "mpls-6cca66c3f170.jg", version: "6.45.2" },
{ crc: 3582919487, size: 4427, name: "ppp.jg", unique: "ppp-9920ae25c111.jg", version: "6.45.2" },
{ crc: 3208363952, size: 66373, name: "roteros.jg", unique: "roteros-0f382eef6476.jg", version: "6.45.2" },
{ crc: 2926347262, size: 8256, name: "roting4.jg", unique: "roting4-13d08e453887.jg", version: "6.45.2" },
{ crc: 3028528262, size: 3919, name: "secure.jg", unique: "secure-531da8b0289e.jg", version: "6.45.2" },
{ crc: 931659009, size: 16994, name: "wlan6.jg", unique: "wlan6-9d9f594b37fb.jg", version: "6.45.2" },
```

## Have you ever used this thing?

Yes! It's quite slow so it takes time, but in June 2019 I used Packet TEL's port 8291 internet-wide scan results from March 2019 to scan for additional information. You can see in the results directory that I found 500,000+ MikroTik hosts in that dataset. Pretty good for a stale dataset if you ask me.


## What are the build dependencies?

This requires:

* Boost 1.66 or higher
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