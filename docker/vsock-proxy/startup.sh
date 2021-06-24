#!/bin/sh

./vsock-proxy server --vsock-port 5006 &
./vsock-proxy test --remote-port 5007 &
sleep 30s
ip link set address 0a:9d:f6:91:fb:73 dev tap0 # This is ethernet address from parent 'ens5' device. This setting will be set using netlink in the future.
ip r add default via 172.31.32.1		 # Default gateway from parent 'ens5' device. This setting will be set using netlink in the future.
#echo "Devices start"  # for debugging purposes
#ip a			# for debugging purposes
#echo "Devices end"	# for debugging purposes
#echo "Routes start"	# for debugging purposes
#ip r			# for debugging purposes
#echo "Routes end"	# for debugging purposes
#echo "Ports start"	# for debugging purposes
#netstat -plant	# for debugging purposes
#echo "Ports end"	# for debugging purposes
arp -i tap0 -s 172.31.32.1 0a:63:7f:97:f3:c9	# This is a copy of ARP entries from parent instance. This setting will be set using netlink in the future.
#echo "ARP start"	# for debugging purposes
#ip neigh		# for debugging purposes
#echo "ARP end"	# for debugging purposes
sleep 100m
