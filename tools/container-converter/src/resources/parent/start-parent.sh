#!/bin/sh
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service

./vsock-proxy proxy --remote-port 5000 --vsock-port 5006 &
