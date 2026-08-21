# Salmiac

A confidential VM running unmodified container images in AMD SEV-SNP, Intel TDX, or AWS [Nitro Enclaves](https://aws.amazon.com/ec2/nitro/).
Salmiac makes it possible to run an application in isolated compute environments to protect and securely process highly sensitive data.

By default, bare Nitro Enclaves doesn't provide any networking capability outside of the enclave environment and neither
Ntiro Enclaves nor SNP have persistent storage, meaning that all your data is lost when container image finishes its execution.

Salmiac enhances Nitro/SNP Enclaves by enabling networking for external communication and providing encrypted persistent storage.

## Useful Links

* :wrench: [Nitro-cli](https://github.com/aws/aws-nitro-enclaves-cli) a tool Salmiac is built on.
* :book: [The Security Design of the AWS Nitro System](https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html), official Nitro Enclaves whitepaper.
* :film_projector: [Presentation](https://archive.fosdem.org/2023/schedule/event/cc_aws/) of Salmiac internals.

## Quick Start Guide

Set up your Ubuntu based build system:
   - Install Rust:
   Follow [this](https://www.rust-lang.org/tools/install) guide.
   - Install Docker:
   Follow [this](https://docs.docker.com/engine/install/) guide to install version 24.0.x
   OR
   ```bash
   apt-get install docker-ce=5:24.0.1-1~ubuntu.20.04~focal docker-ce-cli=5:24.0.1-1~ubuntu.20.04~focal  containerd.io
   ```
   - Install tools needed to build the linux kernel:
   Follow [this](https://kernelnewbies.org/KernelBuild) guide.
   - Install additional dependencies:
   ```bash
   apt-get install pkg-config libclang-dev cmake libpcap-dev
   ```
   * Build `enclave-base` image
   ```bash
   # Run from the root of the repository
   docker build --no-cache -t enclave-base docker/enclave-base 
   ```
### Nitro

This guide allows you to build salmiac from source and convert your docker application into a one that can run in a nitro enclave.


1. Set up your Nitro-enabled AWS EC2 instance:
    - Install docker on your EC2:
      Follow [this](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-docker.html) guide.
    - Install nitro-cli on your EC2:
      Follow [this](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) guide.


2. Build parent base image needed to run container converter
   ```bash
   # Run from the root of the repository
   # Build parent-base-nitro image
   docker build --no-cache docker/nitro/parent-base -t parent-base-nitro
    ```

3. Build the aws nitro blobs. This step takes a long time and needs to be done only once. The artifacts produced by this step need not be cleaned up unless there is an update to the kernel.
   ```bash
   cd salmiac/docker/nitro/amzn-linux-nbd
   ./build-enclave-blobs.sh build
    ```

4. Build the converter image. To produce a debug build of the converter, change FLAVOR to debug from the step below.
    ```bash
   # Run from the root of the repository
   export FLAVOR=release # To produce a debug build of the converter, change the value to `debug`
   export SALMIAC_PLATFORM=nitro # For more info refer to build-support/README.md
   ./build-converter.sh

   # To build nitro converter
   cd docker/$SALMIAC_PLATFORM
   ./build-conv-container.sh $FLAVOR
    ```

5. Create a simple conversion request json file (say /tmp/req.json)
   More details about each field of the conversion request can be found in /salmiac/api-model/src/converter.rs

   ```javascript
   {
      "input_image": {
         "name": "hello-world"
      },
      "output_image": {
         "name": "hello-world-nitro:latest"
      },
      "converter_options": {
         "push_converted_image": false,
         "enable_overlay_filesystem_persistence": false
      },
      "nitro_enclaves_options": {
         "cpu_count": 2,
         "mem_size": "4096M"
      }
   }
   ```

6. Make your application Nitro VM-capable by running container converter with the file from previous step.
   The converter by default pulls the input image and pushes the output image to remote repositories. These images are then cleaned up from the local docker cache. In our example, the output image push is disabled in the request json and to preserve the images in the docker cache, 'PRESERVE_IMAGES' environment variable is specified.
   ```bash
   docker run --rm \
      -e PARENT_IMAGE=parent-base-nitro \
      -e ENCLAVE_IMAGE=enclave-base \
      --name nitro-converter \
      --user 0 \
      --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -e PRESERVE_IMAGES=input,result \
      -v /tmp/req.json:/app/req.json \
      nitro-converter \
      --request-file /app/req.json
    ```

7. Copy converted image into your EC2 instance and run the image.
   Note the use of the environment variable which disables the use of default certificates, which allows you to skip access to Fortanix CCM. Read more about environment variables used in salmiac here - /salmiac/ENV_VARS.md
   ```bash
   # Copy your converted image from step #7 into your EC2 instance
   # ...       
   # Run copied image inside EC2
   docker run -it --rm \
      --privileged \
      -v /run/nitro_enclaves:/run/nitro_enclaves \
      -e ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE=true \
      hello-world-nitro
   ```

### SNP and TDX beta support

The SNP and TDX converters are available for download from Fortanix. Please contact us for a download link.
Ability to build the converter from source will be possible in the future but currently not supported.

1. Create a simple conversion request json file (say /tmp/req.json)
   More details about each field of the conversion request can be found in api-model/docs

   ```javascript
   {
      "input_image": {
         "name": "nginx"
      },
      "output_image": {
         "name": "nginx-tdx"
      },
      "converter_options": {
         "push_converted_image": false,
         "enable_overlay_filesystem_persistence": false
      },
      "snp_enclaves_options": {
         "cpu_count": 2,
         "mem_size": "4096M",
         "enable_gpu_passthrough": false
      }
   }
   ```

2. Make your application SNP or TDX VM-capable by running the relevant container converter with the file from previous step.
   The converter by default pulls the input image and pushes the output image to remote repositories. These images are then cleaned up from the local docker cache. In our example, the output image push is disabled in the request json and to preserve the images in the docker cache, 'PRESERVE_IMAGES' environment variable is specified.
   ```bash
   docker run --rm \
      --name converter \
      --user 0 \
      --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -e PRESERVE_IMAGES=input,result \
      -v /tmp/req.json:/app/req.json \
      converter \
      --request-file /app/req.json
    ```

3. In order to use a converted image with a passthrough GPU, the GPU must first be configured, if this is not already done. The ID's of the GPU must also be found.

   If GPU passthrough is not enabled you may skip this step.

   In order to get the PCI BDF and vendor:device ID's, run

   ```bash
   lspci -D -d 10de:
   # Note the BDF (e.g. 0000:21:00.0) and IDs (e.g. 10de:2330)
   ```

   Save these values for future use.
   On the host machine, run
   
   ```bash
   lspci -nnk -d 10de:
   ```

   If this returns
   
   ```bash
   Kernel driver in use: vfio-pci
   ```

   then you may continue to run the EnclaveOs container image.

   Otherwise, run the following commands (as root), replacing 0000:21:00.0 with your BDF and 10de 2330 with your vendor device ID's:
   
   ```bash
   sudo modprobe vfio-pci
   echo 0000:21:00.0 | sudo tee /sys/bus/pci/devices/0000:21:00.0/driver/unbind 2>/dev/null
   echo 10de 2330 | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id
   ```

   Execute `lspci -nnk -d 10de:` again, and if all is correct, it will be shown that the `vfio-pci` driver is in use.
   
4. To run the container, execute the following command, setting `SNP_GPU_BDF` or `TDX_GPU_BDF` depending on the converter used. Skip passing this variable if GPU passthrough is not configured at conversion time.

   The `APPCONFIG_ID` is the runtime configuration hash of the workflow, which can be created through the CCM UI. It is only necessary for workflows, and not needed if only the application is to be run in the container. Set `APPCONFIG_ID` if one has been created for this instance.

   The variables `ENCLAVEOS_DEBUG` and `RUST_LOG` help with debugging any issues, and can be excluded if more detailed logging is not required.

   ```bash
   docker run \
    --rm \
    --privileged \
    --runtime="runc" \
    -e ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE=false \
    -e ENCLAVEOS_DEBUG=debug \
    -e RUST_LOG=debug \
    -e MEM_SIZE=4096M \
    -e APPCONFIG_ID=0000000000000000000000000000000000000000000000000000000000000000 \
    -e SNP_GPU_BDF=0000:21:00.0 \
    nginx-tdx
   ```

## Releases

The crates within this repository are not published to [crates.io](https://crates.io/), and generally are intended to be
used as `git` references or submodules, and as such, release versioning is tied
to commit hashes and branches.

### Branches

There is a release strategy based on branches,
which follow a naming scheme of `release/salmiac/major.minor`.
Fortanix, while maintaining this repository, will create such release branches at
certain points of development, which are generally tied to [Confidential Computing Manager](https://www.fortanix.com/platform/confidential-computing-manager)
releases.

### Backports

Unlike with tag-based releases, these release branches _may_ have backported changes added to them, so particular
attention _must_ be paid to the branch tip commit, as these may change.
No patch number is used in release branches, making this all the more important.

## Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

### Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

## License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
