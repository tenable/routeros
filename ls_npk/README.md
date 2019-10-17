# List NPK

Parses the NPK format and spits out high level information about the package.

## Whoah buddy. This is complicated. Is there any sample usage?

Sure!

```sh
albinolobster@ns1:~/router/ls_npk/build$ ./ls_npk -f ~/packages/6.41.4/dude-6.41.4.npk 
total size: 1491025
-----------
0: (1) part info, size = 36, offset = 8 -> dude
1: (24) channel, size = 6, offset = 2c
2: (16) architecture, size = 4, offset = 32
3: (2) part description, size = 33, offset = 36
4: (23) digest, size = 40, offset = 57
5: (3) dependencies, size = 34, offset = 7f
6: (22) zero padding, size = 3887, offset = a1
7: (21) squashfs block, size = 1486848, offset = fd0
8: (9) signature, size = 68, offset = 16bfd0
sha1: 3c2b0aa6a70ab758a5872951263fa653cc76dc8c
```

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
