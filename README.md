# slapp-rs

Framework for building MitM applications.

Skip the nasty stuff. Get visibility into the network stack.

> [!IMPORTANT]  
> This project is AI-free. The code is either handwritten or copied from the internet (with references provided). However, AI might be used for architectural design and rubber ducking.

## Known issues

**Interfaces with MTU 65535**

If an interface has the MTU set to 65535 (like loopback has), NFQUEUE [will only provide 65531 bytes at most](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html). The solution is to decrease the MTU or change the interface.


## REMOVE ME

### gdb 

r --log-template /var/log/intercept/intercept.log --node-name polybius --log debug
b __rustc::rust_panic

## Benchmark task

From Claude
> Two smaller things in the same vein: benches in benches/ only see your public API, so mark the core #[doc(hidden)]
pub (or gate a pub mod internal behind a feature and add required-features to the [[bench]] entry).
And make the verdict path a no-op collector rather than a socket write, or you'll be timing syscalls.
