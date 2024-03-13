Salmiac
======


A confidential VM running unmodified container images in AWS [Nitro Enclaves](https://aws.amazon.com/ec2/nitro/).
Salmiac makes it possible to run an application in isolated compute environments to protect and securely process highly sensitive data.

By default bare Nitro Enclaves doesn't provide any networking capability outside of the enclave environment as well
as no persistent storage, meaning that all your data is lost when container image finishes its execution.

Salmiac enhances Nitro Enclaves by enabling networking for external communication and providing encrypted persistent storage.

Useful links
------------

* :wrench: [Nitro-cli](https://github.com/aws/aws-nitro-enclaves-cli) a tool Salmiac is built on.
* :book: [The Security Design of the AWS Nitro System](https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html), official Nitro Enclaves whitepaper.
* :film_projector: [Presentation](https://archive.fosdem.org/2023/schedule/event/cc_aws/) of Salmiac internals.

Quick Start Guide
--------------
This guide allows you to build salmiac from source and convert your docker application into a one that can run in a nitro enclave. 

1. Set up your Ubuntu based build system:
    - Install Rust:
      Follow [this](https://www.rust-lang.org/tools/install) guide.
    - Install Docker:
      Follow [this](https://docs.docker.com/engine/install/) guide.
    - Install tools needed to build the linux kernel:
      Follow [this](https://kernelnewbies.org/KernelBuild) guide.

2. Set up your Nitro-enabled AWS EC2 instance:
    - Install docker on your EC2:
      Follow [this](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-docker.html) guide.
    - Install nitro-cli on your EC2:
      Follow [this](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) guide.


3. Build requisite docker images needed to run container converter
   ```bash
   # Run from the root of the repository
   # build enclave-base image
   cd salmiac/docker/enclave-base
   docker build -t enclave-base .
         
   # build parent-base image
   cd ../parent-base
   docker build -t parent-base .
    ```

4. Build the enclave kernel. This step takes a long time and needs to be done only once. The artifacts produced by this step need not be cleaned up unless the kernel config is updated.
   ```bash
   cd amzn-linux-nbd
   ./build-enclave-kernel.sh build
    ```

5. Build the converter image. To produce a debug build of the converter, ensure the release flag is removed from the step below.
    ```bash
      # Run from the root of the repository
      cd salmiac
      # To produce a debug build of the converter, ensure the release flag is removed from the step below.
      ./build-converter.sh --release

      cd docker
      # If a debug build of the converter was produced, use debug as an argument to the below script
      ./build-conv-container.sh release
    ```

6. Create a simple conversion request json file (say /tmp/req.json)
   More details about each field of the conversion request can be found in /salmiac/api-model/src/converter.rs
   ```javascript
    {
      "input_image": {
         "name": "hello-world", 
      },
      "output_image": {
         "name": "hello-world-nitro",
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

7. Make your application Nitro VM-capable by running container converter with the file from previous step.
   The converter by default pulls the input image and pushes the output image to remote repositories. These images are then cleaned up from the local docker cache. In our example, the output image push is disabled in the request json and to preserve the images in the docker cache, 'PRESERVE_IMAGES' environment variable is specified.
   ```bash
      docker run --rm --name converter --user 0 --privileged -v /var/run/docker.sock:/var/run/docker.sock -e PRESERVE_IMAGES=input,result -v /tmp/req-files:/app converter --request-file /app/req.json
    ```

8. Copy converted image into your EC2 instance and run the image.
   Note the use of the environment variable which disables the use of default certificates, which allows you to skip access to Fortanix CCM. Read more about environment variables used in salmiac here - /salmiac/ENV_VARS.md
   ```bash
      # Copy your converted image from step #7 into your EC2 isntance
      # ...       
      # Run copied image inside EC2
      docker run -it --rm --privileged -v /run/nitro_enclaves:/run/nitro_enclaves -e ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE=true hello-world-nitro
    ```

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

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

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
