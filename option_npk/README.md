# Option NPK

Option NPK appends an extra field to a valid NPK file. The extra field will cause creation of a directory called "/pckg/option". If the package is installed on RouterOS versions 6.41-6.42.0, the option file will enable the backdoor.

```
## Whoah buddy. This is complicated. Is there any sample usage?

Sure!

```sh
albinolobster@ns1:~/router/option_npk/build$ ./option_npk -f ~/packages/6.41.4/dude-6.41.4.npk 
albinolobster@ns1:~/router/option_npk/build$ strings lol.npk | grep pckg/option
../pckg/option
albinolobster@ns1:~/router/option_npk/build$ 
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
