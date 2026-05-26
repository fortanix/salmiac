#!/bin/bash

set -exo pipefail

cloneDependency() {

  # Clone the amazon nitro enclaves bootstrap repository
  if [ -d "aws-nitro-enclaves-sdk-bootstrap" ]; then
    cd aws-nitro-enclaves-sdk-bootstrap
    git fetch
  else
    git clone https://github.com/fortanix/aws-nitro-enclaves-sdk-bootstrap.git
    cd aws-nitro-enclaves-sdk-bootstrap
  fi

}

buildArtifacts() {

  # Build all blobs required by nitro-cli
  docker build -t blobs_all .

  # Once build is complete, we would need a copy of the artifacts
  docker create --name extract_blobs blobs_all
  docker cp extract_blobs:/blobs/  ../
  docker rm extract_blobs

  cd ../
}

cleanDependency() {
  if [ -d "aws-nitro-enclaves-sdk-bootstrap" ]; then
    rm -rf aws-nitro-enclaves-sdk-bootstrap
  fi
}

if [ $1 == "build" ]; then
  cloneDependency;
  buildArtifacts;
elif [ $1 == "clean" ]; then
 cleanDependency;
else
  echo "Provide input arguments - build or clean"
fi

