# A Skeleton Program

A basic program to build WinBox PoC off of.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost, gtest, and cmake. Simply install them like so:

```sh
sudo apt install libboost-dev cmake
```

To compile simply do the following:

```sh
cd routeros/poc/skeleton/
mkdir build
cd build
cmake ..
```

## Usage

```sh
albinolobster@ubuntu:~/routeros/poc/skeleton/build$ ./skeleton --ip 192.168.1.103 --port 8291
```
