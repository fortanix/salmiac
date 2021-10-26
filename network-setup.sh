#!/bin/sh
# script to setup networking before starting Salmiac

# We turn off any network packet handling by the kernel, because 
# networking is handled by vsock-proxy program. Without this setup
# kernel will immediately refuse a TCP connection.
#iptables -A INPUT -m socket -j ACCEPT	# use only in release build
#iptables -P INPUT DROP			# use only in release build

iptables -A INPUT -p tcp --destination-port 5007 -j DROP # default debug setting that only turns off TCP packet handling
