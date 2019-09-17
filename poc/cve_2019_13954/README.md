# CVE-2019-13954

An authenticated user can cause the www binary to consume all memory via a crafted POST request to /jsproxy/upload. When testing the proof of concept on an x86 RouterOS VM, this vulnerability didn't just crash www but caused the whole system to reboot.

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
