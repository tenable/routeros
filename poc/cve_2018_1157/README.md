# CVE-2018-1157

An authenticated user can cause the www binary to consume all memory via a crafted POST request to /jsproxy/upload. When testing our proof of concept on an x86 RouterOS VM, Tenable discovered that this vulnerability didn't just crash www but caused the whole system to reboot.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-all-dev cmake
```

To compile simply do the following:

```sh
cd poc/cve_2018_1157
mkdir build
cd build
cmake ..
```

