# JSProxy PCAP Parser

JSProxy PCAP Parser can parse a PCAP parser session out of a pcap, decrypts it, and spits it out as JSON on the command line.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-dev cmake
```

To compile simply do the following:

```sh
cd jsproxy_pcap_parser
mkdir build
cd build
cmake ..
```

## Usage Example

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
