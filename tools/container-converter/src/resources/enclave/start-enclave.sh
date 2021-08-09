#!/bin/sh

# This is an entry point script for enclave.
# Its main purpose is to setup networking, run vsock-proxy and client command
# Client command is written dynamically to the bottom of this file by the converter.

# setup environment for tap device in case its not present
#mkdir -p /dev/net
#mknod /dev/net/tun c 10 200
#chmod 0666 /dev/net/tun

./vsock-proxy server --vsock-port 5006 --remote-port 8080 &
sleep 30s
ip link set address 0a:9d:f6:91:fb:73 dev tap0
echo "Devices start"
ip a
echo "Devices end"
ip r add default via 172.31.32.1
echo "Routes start"
ip r
echo "Routes end"
echo "Ports start"
netstat -plant
cat /etc/resolv.conf
echo "Ports end"
arp -i tap0 -s 172.31.32.1 0a:63:7f:97:f3:c9
echo "ARP start"
ip neigh
echo "ARP end"
