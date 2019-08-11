##
# This is a very simple script that works on MikroTik's limited busy box. It searches for a
# subset of things that a bad person might do:
#
# 1. Loading /rw/lib/ shared objects into rw
# 2. Use the /rw/RESET file for persistence (pre-6.40.6)
# 3. Use the /rw/DEFCONF file for persistence
# 4. Use /rw/lib for basically anything
# 5. Use /flash/etc/rc.d for run script files (6.40.9 and below)
#
# One thing this does not check is that /pckg/ directories are not malicious. That would be
# pretty good to add.
##

# loop over /proc/*/maps and find
# any /rw/ substrings
for dir in "/proc"/* ; do
    maps=$(cat $dir/maps)
    if [ -z "$maps" ]
    then
        continue
    else
        echo "[+] Searching $dir..."
        target="/rw/"
        if [ -z "${maps##*$target*}" ]
        then
            echo "[!] Found a reference to /rw/ in $dir/maps"
        fi
    fi
done

# find /rw/reset
if [ -f /rw/RESET ]; then
    echo "[!] Found /rw/RESET"
fi

if [ -f /rw/DEFCONF ]; then
    echo "[!] Found /rw/DEFCONF"
fi

if [ -d /rw/lib/ ]; then
    echo "[!] Found /rw/lib"
fi

if [ -d /flash/etc/rc.d ]; then
    echo "[!] Found bad rc directory"
fi

