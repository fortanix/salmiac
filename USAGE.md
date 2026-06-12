# SNP Converter Usage

The SEV-SNP Converter creates EnclaveOs container images using a request file. These images can subsequently be run on
an SEV-SNP capable host.

## Image Conversion

Image conversion requires certain base images to be available in the local Docker cache. If you are not building the
base images separately, they need to be extracted from the converter image. The following steps can be taken to do so:

```bash
# Create a converter container without starting it
docker create --name converter-temp "${converter_image_name}"
# Extract the base image archives
docker cp converter-temp:/app/enclave-base-gpu.tar .
docker cp converter-temp:/app/enclave-base.tar .
docker cp converter-temp:/app/parent-base.tar .
# Remove the converter container
docker rm converter-temp

# Load the base images into the local cache
docker load <enclave-base-gpu.tar
docker load <enclave-base.tar
docker load <parent-base.tar
```

To convert an input image, the image converter must be run. The following command is an example:

```bash
docker run \
  --rm \
  -e RUST_LOG=debug \
  -e ENCLAVEOS_DEBUG=debug \
  --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PRESERVE_IMAGES=input,result \
  -v "${req_file}:/app/req.json" \
  "${converter_image_name}" \
  --request-file "/app/req.json"
```

If custom parent and enclave images are required, the following Docker environmental variables may be added to the
`docker run` command:

```bash
docker run \
  -e PARENT_IMAGE=parent-base \
  -e ENCLAVE_IMAGE=enclave-base \
  # ----- snip -----
```

The following can be used if the custom base images are for a GPU-enabled output image:

```bash
docker run \
  -e PARENT_IMAGE=parent-base \
  -e ENCLAVE_IMAGE=enclave-base-gpu \
  # ----- snip -----
```

The `parent-base`, `enclave-base`, and `enclave-base-gpu` image names should be substituted for the correct custom
names, as they are the defaults, as indicated by the `docker load` step done previously. These custom images must be
present in the local Docker cache to be usable.

The `req.json` file can be substituted with any JSON file containing an SNP Conversion Request.

The conversion request payload looks like this:

```json
{
  "input_image": {
    "name": "private-registry/example:tag",
    "auth_config": {
      "username": "user",
      "password": "password"
    }
  },
  "output_image": {
    "name": "private-registry/example-converted:tag",
    "auth_config": {
      "username": "user",
      "password": "password"
    }
  },
  "converter_options": {
    "allow_docker_pull_failure": false,
    "certificates": [
      {
        "issuer": "ManagerCa",
        "key_type": "Rsa",
        "alt_names": [
          "alt_name"
        ],
        "cert_path": "/path/to/certificate.pem",
        "key_path": "/path/to/private_key.pem"
      }
    ],
    "push_converted_image": true,
    "enable_overlay_filesystem_persistence": false,
    "debug": true,
    "ccm_configuration": {
      "ccm_url": "ccm.fortanix.com:443"
    },
    "dsm_configuration": {
      "dsm_url": "https://apps.sit.smartkey.io/"
    }
  },
  "enclaves_options": {
    "cpu_count": 2,
    "mem_size": "4096M",
    "enable_gpu_passthrough": true
  }
}
```

When launched, the converter will pull the `input_image` (using the optional `auth_config`), and once the process
completes, will place the resulting EnclaveOs image as specified in `output_image` (also with an optional `auth_config`
field).

If needed, zero or more certificates can be configured to be provisioned by CCM during container startup. The mandatory
parameters are the `issuer` and `key_type`. The provided example uses good defaults.

The `alt_name` field accepts a string array as input, but at present, only _one_
alt name is usable in the system.

In order to use the GPU in the converted container, the `enable_gpu_passthrough` option must be set to `true`.

## Running the Image

To run an image, the correct Docker parameters must be used. These will depend on what features are being used. For this
example, the use of a passthrough GPU will be documented.

### Running with a GPU

In order to use a converted image with a passthrough GPU, the GPU must first be configured, if this is not already done.
The ID's of the GPU must also be found.

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

```
Kernel driver in use: vfio-pci
```

then you may continue to run the EnclaveOs container image.

Otherwise, run the following commands (as root), replacing `0000:21:00.0` with your BDF and `10de 2330` with your
`vendor device` ID's:

```bash
sudo modprobe vfio-pci
echo 0000:21:00.0 | sudo tee /sys/bus/pci/devices/0000:21:00.0/driver/unbind 2>/dev/null
echo 10de 2330 | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id
```

Execute `lspci -nnk -d 10de:` again, and if all is correct, it will be shown that the `vfio-pci` driver is in use.

To run the container, execute the following command, setting `SNP_GPU_BDF`
using the value obtained previously, and set
`APPCONFIG_ID` if one has been created for this instance.

The `APPCONFIG_ID` is the runtime configuration hash of the workflow, which can be created through the CCM UI. It is
only necessary for workflows, and not needed if only the application is to be run in the container.

The variables `ENCLAVEOS_DEBUG` and `RUST_LOG` help with debugging any issues, and can be excluded if more detailed
logging is not required.

```bash
docker run \
  -it \
  --privileged \
  --runtime=runc \
  -e ENCLAVEOS_DEBUG=debug \
  -e RUST_LOG=debug \
  -e APPCONFIG_ID=0000000000000000000000000000000000000000000000000000000000000000 \
  -e SNP_GPU_BDF=0000:21:00.0 \
  private-registry/example-converted:tag
```

This should run the container, and execute the payload inside the container.