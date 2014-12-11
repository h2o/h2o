Run the commands below to create a new certificate signed by the CA:

```
openssl genrsa -out server.key 2048
openssl req -days 3650 -new -key server.key -out server.csr
openssl ca -keyfile ca.key -cert ca.crt -extensions usr_cert -policy policy_anything -days 3650 -md sha256 -in server.csr -out server.crt
```
