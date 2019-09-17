# RouterOS Security Research

This repository contains various tools and exploits developed while performing security research on MikroTik's RouterOS. The various projects are broken up into the following subdirectories:

* **8291_honeypot**: A honeypot that listens for Winbox messages.
* **8291_scanner**: A scanner that attempts to talk Winbox to a provided list of IP addesses.
* **brute_force**: A couple of tools for guessing the admin password on the winbox and www interfaces.
* **cleaner_wrasse**: A tool to enable the devel backdoor on the majority of RouterOS releases.
* **common**: Winbox and JSProxy implementations used across multiple projects.
* **modify_npk**: A tool that overwrites an NPK's squashfs section with a new squashfs.
* **msg_re**: Tools for discovering Winbox message routing and handlers.
* **pcap_parsers**: Various tools that parse Winbox or JSProxy pcap files.
* **poc**: Proof of concept exploits.
* **slides**: Slides from talks given on this repositories material.
* **tests**: A set of unit tests that test the Winbox/JSProxy implementations

For much more detail drill down into the individual directories.

## Compilation Requirements

Almost everything here is written in C++ (there are only two exceptions). In order to compile everything you'll need:

* cmake
* Boost 1.66 or higher

For a couple of projects you'll also need:

* libpcap-dev
* libgeoip-dev
* libgtest-dev
* [Geolite2++](https://www.ccoderun.ca/GeoLite2++/api/usage.html)
* [libmaxminddb](https://github.com/maxmind/libmaxminddb)

Each project should contain specific instructions but, in general, the following should be sufficient.
```sh
mkdir build
cd ./build/
cmake ..
make
```
## Submitting an Issue

When submitting an issue, please ensure that you have included sufficient information to reproduce the issue. Test files, pcaps, and step by step guides are always welcome. Also, please keep in mind that we only support the following OS:

* Ubuntu 19.04+

## Submitting a Pull Request

When submitting a pull request, please try to provide proof that you tested your work. Indicate how I can test it and perhaps most importantly, please try to not to stray from my coding style... as terrible as it is.

## License

This repository is released under the 3-clause BSD license. See the LICENSE file for details.

## Other Projects

There are other researchers doing neat RouterOS work. Here are a few I know of:

* https://github.com/0ki/mikrotik-tools
* https://github.com/BigNerd95/Chimay-Red
* https://github.com/BigNerd95/Chimay-Blue
* https://github.com/rsa9000/npk-tools
