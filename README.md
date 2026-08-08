# snarf-rs

Framework for building MitM applications.

Skip the nasty stuff. Get visibility.

## Known issues

**Interfaces with MTU 65535**

If an interface has the MTU set to 65535 (like loopback has), NFQUEUE [will only provide 65531 bytes at most](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html). The solution is to decrease the MTU or change the interface.
