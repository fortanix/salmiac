#!/bin/sh

./vsock-proxy server --vsock-port 5006 &
./vsock-proxy test --remote-port 5007 &
sleep 20s
ip link set address 0a:9d:f6:91:fb:73 dev tap0 # This is ethernet address from parent 'ens5' device. This setting will be set using netlink in the future.
ip r add default via 172.31.32.1		 # Default gateway from parent 'ens5' device. This setting will be set using netlink in the future.

