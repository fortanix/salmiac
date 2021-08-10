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
echo "Devices start"
ip a
echo "Devices end"
echo "Routes start"
ip r
echo "Routes end"
echo "Ports start"
netstat -plant
cat /etc/resolv.conf
echo "Ports end"
echo "ARP start"
ip neigh
echo "ARP end"
