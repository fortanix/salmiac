# AWS Nitro enclaves #

TODO: Make a complete list of environment variables used by the project

## Environment variables

Format used to describe the variables - key name -- description -- example (optional)

The following list of variables are used while running the converted salmiac image.

##### Filesystem related variables
- FS_API_KEY - API key used for authenticating with DSM if the salmiac app is not converted with app
  certs enabled.

##### Environment variables that help with application certificates
- ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE - If set, can be used to skip fetching
  a default certificate from CCM
- NODE_AGENT - The url of the nitro node agent which can be used by salmiac
  to request application certificates

Note - Application certificates can't be issued by CCM when ENCLAVEOS_DEBUG is
set i.e. when the enclave is running in debug mode. Unless the build/app is
registered as a debug build in a test-only deployment account.

##### Logging related variables
- ENCLAVEOS_DEBUG - Set to debug to run the enclave in debug mode.
- RUST_LOG - Set to debug to enable generic Rust debug logging for the enclave parent.

##### Nitro enclaves settings variables
- CPU_COUNT - Override the --cpu-count param passed while running the enclave i.e.
  passed to the nitro-cli run command.
- MEM_SIZE - Override the --memory param passed while running the enclave i.e.
  passed to the nitro-cli run command.

##### AMD SEV-SNP enclaves settings variables
- SNP_GPU_BDF - For use with EnclaveOS containers with GPU passthrough.
  Consists of the BDF (Bus/Device/Function) of the GPU to be used.
- SNP_CPU - QEMU CPU type, defaults to `EPYC-v4,-tsa-sq-no,-tsa-l1-no,family=0,model=0,stepping=0`.
- SNP_CBITPOS - Since SNP is only supported from processor series 7003 and newer,
  the c-bit (cbitpos) will always be 51. Defaults to `51`.
  See this [document](https://docs.amd.com/v/u/en-US/58207-using-sev-with-amd-epyc-processors).
- SNP_REDUCED_PHYS_BITS - Defaults to `1`
- SNP_POLICY - Defaults to `0x20000`, to disable SMT.
