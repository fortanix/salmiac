# AWS Nitro enclaves #

TODO: Make a complete list of environment variables used by the project

## Environment variables

Format used to describe the variables - key name -- description -- example (optional)

The following list of variables are used while running the converted salmiac image.

##### Filesystem related variables
- FS_DSM_ENDPOINT - Override the default value of DSM_ENDPOINT used for filesystem persistence.
  The default value is "https://amer.smartkey.io/"
- FS_API_KEY - API key used for authenticating with DSM if the salmiac app is not converted with app
  certs enabled.

##### Logging related variables
- ENCLAVEOS_DEBUG - Set to debug to run the enclave in debug mode.

##### Nitro enclaves settings variables
- CPU_COUNT - Override the --cpu-count param passed while running the enclave i.e.
  passed to the nitro-cli run command.
- MEM_SIZE - Override the --memory param passed while running the enclave i.e.
  passed to the nitro-cli run command.