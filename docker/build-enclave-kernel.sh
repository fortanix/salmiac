#!/bin/bash

set -exo pipefail

ARTIFACT_NAME="amzn-linux-nbd.tar"
ARTIFACT_DIR="amzn-linux-nbd"
fetchartifacts() {
  aws s3 cp s3://fortanix-internal-artifact-repository/salmiac/amzn-linux-nbd.tar .
  tar -xvf $ARTIFACT_NAME
}

cleanartifacts() {
  if [ -f $ARTIFACT_NAME ];
    then rm $ARTIFACT_NAME
  fi

  if [ -d $ARTIFACT_DIR ];
    then rm -rf $ARTIFACT_DIR
  fi
}

buildkernel() {
  # Clone the amazon linux kernel repository and checkout
  # the branch which is used for nitro enclaves
  # You can find out the kernel version used by nitro-enclaves
  # by running uname -a in a converted app. In this case, we
  # use version 4.14.246
  if [ -d "linux" ]; then
    cd linux
    git fetch
  else
    git clone https://github.com/amazonlinux/linux.git
  fi

  git checkout microvm-kernel-4.14.246-198.474.amzn2

  # Copy the enclave kernel config file into the kernel repository
  # This file was copied from $(NITRO_INSTALL_DIR)/blobs/ directory of
  # an amazon EC2 instance where nitro enclaves can run.
  # NITRO_INSTALL_DIR is by default set ot /usr/share/nitro_enclaves
  fetchartifacts;
  cp $ARTIFACT_DIR/bzImage.config .config
  cleanartifacts

  # Build the enclave kernel
  make prepare && make modules_prepare && make modules && make && make bzImage

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
  buildkernel;
elif [ $1 == "fetch" ]; then
  fetchartifacts;
elif [ $1 == "clean" ]; then
 cleanartifacts;
 cleankernel;
else
  echo "Provide input arguments - build or fetch or clean"
fi

