Steps followed to generate the client certificate used for testing.
Similar steps can be followed if you need to generate another client certificate with app id embedded in it.

1. Download the key material of "SafeAI-Test-App CA Private Key" sobject from Fortanix account of amer.smartkey.io.
File saved as safeai_test_app_ca_private_key-Raw.bin
2. Download the trusted CA of "SafeAI-Test-App" App from Fortanix account of amer.smartkey.io
This CA was created with the following command:
openssl req -x509 -new -nodes -key safeai_test_app_ca_private_key-Raw.bin -sha256 -days 3650 -out ca.crt -subj "/C=NL/ST=NB/L=Eindhoven/O=Fortanix/CN=AgentCA"
File saved as ca.crt
3. Generate the client key:
openssl genrsa -out client.key 2048
4. Generate a CSR for the client:
openssl req -new -key client.key -out client.csr -subj "/O=Fortanix/CN=DSMUnitTestClient"
5. Generate an extension file along with the DNS name that matches that of the trusted CA cert:

```basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = AgentCA
DNS.2 = localhost
```
5. Sign the CSR and generate a CA signed client certificate (expiry set to 5 years):
openssl x509 -req -in client.csr -CA ca.crt -CAkey safeai_test_app_ca_private_key-Raw.bin -CAcreateserial -out client.cert -days 1825 -sha256 -extfile client.ext