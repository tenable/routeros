# Get Policies

This program interrogates all of the RouterOS handlers to find out what commands the support and what policy is associated with that commands. The program requires the input of two csv:

* one from parse_x3 that tells the program all the system to mappings
* one from handler_csv that tells the program all the system's registered handlers

The result is that we can find the entire attack surface of RouterOS (via the message protocol) and the authentication required to touch all endpoints.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

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

## Usage Example

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
