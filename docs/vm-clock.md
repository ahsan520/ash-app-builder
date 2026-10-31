# Keeping VirtualBox VM clocks right

**Symptom (seen 2026-10-31):** a VM's clock jumps (about 3 hours behind, or `RTC time` days ahead) after the Mac sleeps or the VM is paused or restored. Heartbeats fail ("Failed to connect ... port 30443"), brokers show "Refused: clock skew" and "Collector disconnected" alerts open and close all day. `chronyc makestep` fixes it by hand.

**Cause:** chrony's default `makestep 1 3` steps the clock only during its first 3 updates after start. After that it only slews (a few hundred ppm), so a jump of minutes or hours is never corrected on its own.

**Fix (run on the ASIX k3s VM and on every broker VM):**
```
sudo scripts/deploy/fix-vm-clock.sh --install
```
It writes `/etc/chrony/conf.d/asix-makestep.conf` (`makestep 1 -1`: step whenever more than 1 second off), restarts chrony, and installs the timer `asix-fix-vm-clock.timer` (every minute: if `chronyc tracking` says the offset is above `ASIX_CLOCK_MAX_OFFSET`, default 1 second, it runs `chronyc burst 4/4` and `chronyc makestep`). `--remove` undoes both; `--check` is what the timer runs. Check it: `systemctl list-timers asix-fix-vm-clock.timer`, `journalctl -u asix-fix-vm-clock`, `chronyc tracking`. The Ubuntu package `chrony` must be installed (it is where `chronyc` works).

**Tested** with stand-ins for `chronyc` and `systemctl` (`tests/vm-clock-script.test.js`); **not yet run on a real VM**.

**Also worth doing on the Mac (not scripted):** a sleeping Mac pauses the VMs. Keep it awake while ASIX runs (`sudo pmset -a sleep 0 disablesleep 1`, or `caffeinate -s` in a terminal) and, if Guest Additions are installed in the VM, let VirtualBox set the time on resume: `VBoxManage guestproperty set "<vm name>" "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold" 1000` (host side, VM restart needed). A real server does not have this problem.
