# ><(((°> Cleaner Wrasse <°)))><

Cleaner Wrasse is a tool that remotely enables the hidden busybox shell in routers using RouterOS versions 3.x - 6.43.14. CW doesn't care about the router's architecture or any periphials. It should *just work*. Once enabled, the hidden shell allows the *devel* user to login with the admin's password over telnet or SSH. The  user is then presented with a root shell. It's damn useful.

### Usage Example:
```sh
albinolobster@ubuntu:~/routeros_internal/cleaner_wrasse/build$ ./cleaner_wrasse -i 192.168.1.22 -u admin -p lolwat

            ><(((°>         ><(((°>         ><(((°> 
           ╔═╗┬  ┌─┐┌─┐┌┐┌┌─┐┬─┐  ╦ ╦┬─┐┌─┐┌─┐┌─┐┌─┐
           ║  │  ├┤ ├─┤│││├┤ ├┬┘  ║║║├┬┘├─┤└─┐└─┐├┤ 
           ╚═╝┴─┘└─┘┴ ┴┘└┘└─┘┴└─  ╚╩╝┴└─┴ ┴└─┘└─┘└─┘
                    <°)))><         <°)))><         

   "Cleaners are nothing but very clever behavioral parasites"

[+] Trying winbox on 192.168.1.22:8291
[+] Connected on 8291!
[+] Logging in as admin
[+] Login success!
[+] Sending a version request
[+] The device is running RouterOS 6.43.14 (long-term)
[+] The backdoor location is /pckg/option
[+] We only support 1 vulnerability for this version 
[+] You've selected CVE-2019-3943. What a fine choice!
[+] Opening //./.././.././../rw/DEFCONF for writing.
[+] Writing to file.
[+] Done! The backdoor will be active after a reboot. ><(((°>
[?] Reboot now [Y/N]? Y
[+] Sending a reboot request
albinolobster@ubuntu:~/routeros_internal/cleaner_wrasse/build$ telnet -l devel 192.168.1.22
Trying 192.168.1.22...
Connected to 192.168.1.22.
Escape character is '^]'.
Password: 


BusyBox v1.00 (2019.04.02-09:33+0000) Built-in shell (ash)
Enter 'help' for a list of built-in commands.

# 
```

## What problem are you trying to solve?

RouterOS devices have seen a lot of exploitation over the last couple of years. That sucks, but what sucks more is that there is no way to know if your device was exploited (unless the attacker makes obvious mistakes). RouterOS provides no mechanism for normal users to inspect the underlying Linux OS. Cleaner Wrasse attempts to fix this problem. By enabling the backdoor and providing a simple scanning tool (wrasse.sh), administrators can better understand if they were exploited and what that means for their network/enterprise/ISP.

## How does it work?

The user provides Cleaner Wrasse with the IP of the router, a username, and a password. CW will then try to talk to the router over port 8291 (winbox) or port 80 (www). Once connected, CW will attempt to exploit the router using CVE-2019-3943, CVE-2018-14847, or the HackerFantastic set tracefile trick in order to enable the backdoor.

There is a lot more going on under the hood but that is a good overview.

## What versions can CW enable the backdoor on?

The tool *should work* on the following versions:

* Longterm: 6.30.1 - 6.43.14
* Stable: 3.30 - 6.43.12

The tool *cannot exploit* the the following versions:

* Longterm: 6.43.15 - current (6.44.5)
* Stable: 6.44 - current (6.45.2)

Due to some protocol changes, the tool can't even talk to version 6.45+.

## Which architectures are supported though?

All of them. Cleaner Wrasse relies on simple file creation vulnerabilities. No shell code is required. No compiling .so for various architectures. Just simple file creation and rc scripts.

## This requires auth?

Indeed. Not only do the vulns (mostly) require authentication, but this isn't really intended to be an offensive tool (although, really anything is).

## Wait, www doesn't work for all the advertised versions!

That's true! MikroTik rolled out a new authentication / encryption scheme for the web interface in 6.43.0. I haven't had time to figure that out yet. Sorry! Also, really old versions of www don't quite follow the same encryption scheme either. As long as you stay in 6.0 - 6.42 land, you'll be fine. I'm not perfect you know!

## Does the backdoor go away if I reboot the system?

That depends on the version! Before 6.41 the backdoor would persist across reboots. Since 6.41 the backdoor has been moved to tmpfs space. However, if you ask it to, CW will install the backdoor file in such a way that it will survive reboots.

## How does reboot persistence in 6.41+ work?

CW installs a file called DEFCONF in /rw/. On startup, RouterOS will execute the contents of that file. The CW version of DEFCON creates the backdoor file and creates an rc script that will generate a new DEFCONF file on shutdown (thus restarting the cycle).

This has one nasty side affect: Upgrading silently fails. In order to re-enable upgrading you'll need to use the devel backdoor to rm /rw/.lol

## Can CW survive upgrades?

That is a bit trickier! For now, Cleaner Wrasse can create a symlink to root in the user's directory. From there, you can easily recover the root shell. The beauty(?) of the symlink that CW creates is that it will survive all upgrades and reboots but also isn't visible in Winbox or Webfig.

## What about the unsupported versions?

Cleaner Wrasse simply can't talk to the new versions of Winbox (6.45) and JSProxy (6.43). Some lazy git hasn't worked out how they work yet. But also, newer versions have patched the vulnerabilities I'm using in CW. If you have a version that CW can't exploit but you want to get the devel shell, this is what I recommend:

* Downgrade to 6.43.14 Long-term
* Use CW to drop a symlink in the user's directory
* Reboot
* Upgrade back to wherever you were.
* FTP into the router and traverse the symlink to arrive at /rw/
* put DEFCONF
* Reboot
* Done!

At least, that's how I'm maintaining the backdoor on my rb750. YMMV.

## What is wrasse.sh?

wrasse.sh is a script that will look for signs of exploitation in your device. It was developed to work on the very limited busybox shell on the router.

## What kind of name is Cleaner Wrasse?

A [cleaner wrasse](https://en.wikipedia.org/wiki/Bluestreak_cleaner_wrasse) is a [cleaner fish](https://en.wikipedia.org/wiki/Cleaner_fish). It forms a symbiotic relationship with other fish. The cleaner wrasse eats the parasites off of the other fish. However, unlike other cleaners, the cleaner wrasse is also known to occassionally take a bite out of their fish buddy. I thought that really captured what we are doing here.

## Will this software hurt my router?

Maybe? Nothing is perfect. Maybe Cleaner Wrasse breaks something on your router. It shouldn't, but who knows? Please understand the LICENSE and understand that this is open source software written by some random guy.

## But seriously, is this dangerous?

I mean, sure, a little bit. Not only are you running code you probably don't understand but you're doing unsupported stuff to your router. Also, *the implementation of the Winbox protocol this tool uses doesn't use any type of encryption*... so... something to think about.
