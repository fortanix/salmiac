#!/bin/bash
set -eo pipefail

TESTS_CONTAINER=$1
FORTANIX_API_KEY=$2

SSH_USERNAME_AWS="ec2-user"
VM_ADDRESS="ec2-63-35-198-180.eu-west-1.compute.amazonaws.com"

echo "######### Preparing test container. ###############"
touch docker-env
echo "AWS_CONFIG=$(/usr/bin/base64 --wrap=0 < ~/.aws/config)" > docker-env
echo "AWS_CREDENTIALS=$(/usr/bin/base64 --wrap=0 < ~/.aws/credentials)" >> docker-env

ECR_PASSWORD=$(aws ecr get-login-password --region us-west-1)
echo "ECR_PASSWORD=$ECR_PASSWORD" >> docker-env

PARENT_IMAGE=fortanix/parent-base:1.2.0
echo "PARENT_IMAGE=$PARENT_IMAGE" >> docker-env

ENCLAVE_IMAGE=fortanix/enclave-base:1.1.0
echo "ENCLAVE_IMAGE=$ENCLAVE_IMAGE" >> docker-env

echo "FORTANIX_API_KEY=$FORTANIX_API_KEY" >> docker-env

docker pull $TESTS_CONTAINER
docker save $TESTS_CONTAINER -o salmiac-tests-container.tar.gz

SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -o ServerAliveInterval=60"

echo "######### Copying tests container to Nitro VM. ###############"
scp $SSH_OPTS salmiac-tests-container.tar.gz $SSH_USERNAME_AWS@$VM_ADDRESS:~/salmiac-tests-container.tar.gz
scp $SSH_OPTS docker-env $SSH_USERNAME_AWS@$VM_ADDRESS:~/docker-env

docker pull $PARENT_IMAGE
docker save $PARENT_IMAGE -o parent-base.tar.gz
echo "######### Copying parent base container to Nitro VM. ###############"
scp $SSH_OPTS parent-base.tar.gz $SSH_USERNAME_AWS@$VM_ADDRESS:~/parent-base.tar.gz

docker pull $ENCLAVE_IMAGE
docker save $ENCLAVE_IMAGE -o enclave-base.tar.gz
echo "######### Copying enclave base container to Nitro VM. ###############"
scp $SSH_OPTS enclave-base.tar.gz $SSH_USERNAME_AWS@$VM_ADDRESS:~/enclave-base.tar.gz

echo "######### Check Connection to Nitro VM. ###############"
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS echo ok
echo "######### Check Sucess###############"

echo "######### Start Test ###############"
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker load -i parent-base.tar.gz
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker load -i enclave-base.tar.gz
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker load -i salmiac-tests-container.tar.gz
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS rm salmiac-tests-container.tar.gz enclave-base.tar.gz parent-base.tar.gz
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker tag $PARENT_IMAGE parent-base
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker tag $ENCLAVE_IMAGE enclave-base

ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker run --privileged --env-file docker-env -v /var/run/docker.sock:/var/run/docker.sock --network host $TESTS_CONTAINER

echo "######### Delete test images ###############"
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS rm docker-env
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS docker logout
ssh $SSH_OPTS $SSH_USERNAME_AWS@$VM_ADDRESS 'yes | docker system prune -a'

docker image rm -f $TESTS_CONTAINER
