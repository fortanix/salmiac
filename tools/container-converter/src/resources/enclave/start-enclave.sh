#!/bin/sh
./vsock-proxy server --vsock-port 5006 --remote-port 5007 &
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
