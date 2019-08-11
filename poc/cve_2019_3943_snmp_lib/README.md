# CVE-2019-3943 snmp dlopen PoC

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC creates the directory //./.././.././../ram/pckg/snmp_xploit/nova/lib/snmp/ and uploads an x86 shared object called lol.so. The shared object will be dlopen'ed by snmp when it starts up. The dlopen will cause the shared object to execute:

```
void __attribute__((constructor)) lol(void)
{
    system("rm -rf /ram/pckg/snmp_xploit; mkdir /pckg/option; mount -o bind /boot/ /pckg/option;");
}
```
In order to ensure the shared object is picked up, the PoC will stop and start the SNMP process.


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

