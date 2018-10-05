# JSProxy PCAP Password Bruteforce

Given a PCAP and a password list, this project will try to brute force the password of an observed web login.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-dev cmake
```

To compile simply do the following:

```sh
cd jsproxy_pcap_password_bruteforce
mkdir build
cd build
cmake ..
```

## Usage Example

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
