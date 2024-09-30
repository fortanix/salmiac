#!/bin/bash

set -exo pipefail

# SALM-352 - Update kernel to not display developer's name and machine
# information
ARTIFACT_NAME="amzn-linux-nbd-v1.tar"
ARTIFACT_DIR="amzn-linux-nbd"
fetchartifacts() {
  aws s3 cp https://s3.us-west-1.amazonaws.com/downloads.fortanix.com/salmiac/$ARTIFACT_NAME .
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

if [ $1 == "fetch" ]; then
  fetchartifacts;
elif [ $1 == "clean" ]; then
  cleanartifacts;
else
  echo "Provide input arguments - fetch or clean"
fi

