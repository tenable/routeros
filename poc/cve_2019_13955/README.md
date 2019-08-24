# CVE-2019-13955

An unauthenticated user communicating with the www binary can trigger a stack exhaustion vulnerability via recursive parsing of JSON.

## Backtrace

From 6.44.3:
```sh
Program received signal SIGSEGV, Segmentation fault.
[Switching to LWP 406]
0x7745e9bf in ?? () from /nova/lib/www/jsproxy.p
(gdb) bt
#0  0x7745e9bf in ?? () from /nova/lib/www/jsproxy.p
#1  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#2  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#3  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#4  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#5  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#6  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#7  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#8  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#9  0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#10 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#11 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#12 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#13 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#14 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#15 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#16 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#17 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#18 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#19 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#20 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
#21 0x7745f333 in ?? () from /nova/lib/www/jsproxy.p
---Type <return> to continue, or q <return> to quit---
```

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

## Usage

```sh
albinolobster@ubuntu:~/routeros/poc/cve_2019_13955/build$ ./cve_2019_13955_poc -i 192.168.1.38
read_until: End of file
{}
```


