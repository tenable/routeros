# CVE-2018-1159

An authenticated user can cause memory corruption in the www binary by rapidly authenticating and disconnecting. Tenable's proof of concept generates the following crash dump. Note that due to the nature of memory corruption this exact stack trace will be very difficult to reproduce:

```sh
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: /nova/bin/www
2018.05.25-11:11:54.39@0: --- signal=11 --------------------------------------------
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: eip=0x7755a130 eflags=0x00010212
2018.05.25-11:11:54.39@0: edi=0x746e6f43 esi=0x0000007b ebp=0x77588078 esp=0x7758806b
2018.05.25-11:11:54.39@0: eax=0x08063564 ebx=0x7755bbe8 ecx=0x08062a30 edx=0x08062a34
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: maps:
2018.05.25-11:11:54.39@0: 08048000-0805c000 r-xp 00000000 00:0b 1111       /nova/bin/www
2018.05.25-11:11:54.39@0: 77557000-7755b000 r-xp 00000000 00:0b 980        /lib/libucrypto.so
2018.05.25-11:11:54.39@0: 7755c000-77566000 r-xp 00000000 00:0b 1014       /nova/lib/www/jsproxy.p
2018.05.25-11:11:54.39@0: 77589000-775be000 r-xp 00000000 00:0b 997        /lib/libuClibc-0.9.33.2.so
2018.05.25-11:11:54.39@0: 775c2000-775dc000 r-xp 00000000 00:0b 993        /lib/libgcc_s.so.1
2018.05.25-11:11:54.39@0: 775dd000-775ec000 r-xp 00000000 00:0b 977        /lib/libuc++.so
2018.05.25-11:11:54.39@0: 775ed000-77735000 r-xp 00000000 00:0b 987        /lib/libcrypto.so.1.0.0
2018.05.25-11:11:54.39@0: 77744000-77788000 r-xp 00000000 00:0b 989        /lib/libssl.so.1.0.0
2018.05.25-11:11:54.39@0: 7778c000-7779b000 r-xp 00000000 00:0b 995        /lib/libpthread-0.9.33.2.so
2018.05.25-11:11:54.39@0: 7779f000-777a1000 r-xp 00000000 00:0b 992        /lib/libdl-0.9.33.2.so
2018.05.25-11:11:54.39@0: 777a3000-777a6000 r-xp 00000000 00:0b 981        /lib/libuxml++.so
2018.05.25-11:11:54.39@0: 777a7000-777f2000 r-xp 00000000 00:0b 979        /lib/libumsg.so
2018.05.25-11:11:54.39@0: 777f8000-777ff000 r-xp 00000000 00:0b 991        /lib/ld-uClibc-0.9.33.2.so
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: stack: 0x7ff2d000 - 0x7758806b 
2018.05.25-11:11:54.39@0: 77 43 6f 6e 74 7b 00 00 00 00 00 00 00 a8 80 58 77 3f a2 55 77 64 35 06 08 0c 36 06 08 26 00 00 
2018.05.25-11:11:54.39@0: 00 20 a2 55 77 f0 80 58 77 ec c4 5e 77 b8 80 58 77 58 62 56 77 64 35 06 08 e8 80 58 77 c8 80 58 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: code: 0x7755a130
2018.05.25-11:11:54.39@0: 8a 14 38 88 55 f3 0f b6 fa 8b b0 04 01 00 00 01 
2018.05.25-11:11:54.39@0: 
2018.05.25-11:11:54.39@0: backtrace: 0x7755a130 0x7755a23f 0x77562821 0x77564ef1 0x77565369 0x7756122b 0
```

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-all-dev cmake
```

To compile simply do the following:

```sh
cd poc/cve_2018_1159
mkdir build
cd build
cmake ..
```

