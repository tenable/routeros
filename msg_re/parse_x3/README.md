# Loader X3 Parser

The x3 parser parses the /nova/etc/loader/system.x3 file and spits out each binary's SYSTEM TO mapping.

## Dependencies

* Boost
* CMake

## How to Build
The following was tested on Ubuntu 18.04

```sh
sudo apt install libboost-all-dev
sudo apt install cmake
cd parse_x3/
mkdir build
cd build
cmake ..
make
```

## How to Use

```sh
./x3_parse -f ../example/system_6_43_45.x3 
/nova/bin/log -> 3
/nova/bin/radius -> 5
/nova/bin/moduler -> 6
/nova/bin/user -> 13
...
```
