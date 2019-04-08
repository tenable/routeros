# CVE-2018-1158

An authenticated user communicating with the www binary can trigger a stack exhaustion vulnerability via recursive parsing of JSON.

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost and cmake. Simply install them like so:

```sh
sudo apt install libboost-all-dev cmake
```

To compile simply do the following:

```sh
cd poc/cve_2018_1158
mkdir build
cd build
cmake ..
```

