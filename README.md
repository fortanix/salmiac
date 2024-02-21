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

1. Install Rust:
   Follow [this](https://www.rust-lang.org/tools/install) guide.


2. Install Docker:
   Follow [this](https://docs.docker.com/engine/install/) guide.


3. Set up your Nitro-enabled AWS EC2 instance:
    - Install docker on your EC2:
      Follow step #2
    - Install nitro-cli on your EC2:
      Follow [this](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) guide.


4. Build requisite docker images needed to run container converter
   ```bash
   # Run from the root of the repository
   # build enclave-base image
   cd salmiac/docker/enclave-base
   docker build -t enclave-base .
         
   # build parent-base image
   cd ..//parent-base
   docker build -t parent-base .
    ```

5. Compile container converter:
    ```bash
      # Run from the root of the repository
      cd salmiac
      ./build-converter.sh   
    ```

6. Create a simple conversion request json file
   ```javascript
    {
      "input_image": {
         "name": "<your application image tag>",         
      },
      "output_image": {
         "name": "<your output image tag>",            
      },
      "converter_options": {
         "debug": true
      },
      "nitro_enclaves_options": {
         "cpu_count": 2,
         "mem_size": "4096M"
      }
   }
   ```

7. Make your application Nitro VM-capable by running container converter with the file from previous step
   ```bash
      # Run from the root of the repository
      cd tools/container-converter/target/debug
      ./container-converter --request-file <path to file from step 4>
    ```

8. Copy converted image into your EC2 instance and run the image
   ```bash
      # Copy your converted image from step #7 into your EC2 isntance
      # ...       
      # Run copied image inside EC2
      docker run -it --rm --privileged -v /run/nitro_enclaves:/run/nitro_enclaves <your image name>
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