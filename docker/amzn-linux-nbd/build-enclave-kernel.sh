#!/bin/bash

set -exo pipefail

clonelinux() {

  # Clone the amazon linux kernel repository and checkout
  # the branch which is used for nitro enclaves
  # You can find out the kernel version used by nitro-enclaves
  # by running uname -a in a converted app. In this case, we
  # use version 4.14.246
  # For more details about supported nitro enclave kernel
  # versions, refer to the aws-nitro-enclaves-cli github repository.

  if [ -d "linux" ]; then
    cd linux
    git fetch
  else
    git clone https://github.com/amazonlinux/linux.git
    cd linux
  fi

  git checkout microvm-kernel-4.14.246-198.474.amzn2

}

buildkernel() {

  # Copy the enclave kernel config file into the kernel repository
  # The original file is available here:
  # https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/x86_64/bzImage.config
  # The config file available in this directory has been updated to
  # support salmiac features.
  cp ../bzImage.config .config

  # Build the enclave kernel
  make prepare
  make modules_prepare
  make modules
  make
  make bzImage

  # Once build is complete, we would need a copy of the bzImage file
  cp ./arch/x86/boot/bzImage ../
  cp .config ../bzImage.config

  cd ../
}

cleankernel() {
  if [ -d "linux" ]; then
    rm -rf linux
  fi
}

if [ $1 == "build" ]; then
  clonelinux;
  buildkernel;
elif [ $1 == "clean" ]; then
 cleankernel;
else
  echo "Provide input arguments - build or clean"
fi

