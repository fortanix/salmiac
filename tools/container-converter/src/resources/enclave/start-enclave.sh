#!/bin/bash

mount -t proc /proc proc/
echo "Mount /proc"

mount --rbind /sys sys/
echo "Mount /sys"

mount --rbind /dev dev/
echo "Mount /dev"
