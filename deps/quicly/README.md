quicly
===

Quicly is a QUIC implementation, written from the ground up to be used within the H2O HTTP server.

The software is licensed under the MIT License.

How to build
---

```
% git submodule update --init --recursive
% cmake .
% make
```

Building the software requires OpenSSL 1.0.2 or above.
If you have OpenSSL installed in a non-standard directory, you can pass the location using the `PKG_CONFIG_PATH` environment variable.

```
% PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig cmake .
```

How to test
---

Install dependencies first:

```
# If you use system perl, use --sudo
% curl -sL https://cpanmin.us | perl - --sudo --self-upgrade
% cpanm --installdeps --notest --sudo .

# Otherwise, you'd better omit --sudo
% curl -sL https://cpanmin.us | perl - --self-upgrade
% cpanm --installdeps --notest .
```

Then, run the tests:
```
% make check
```

Running quicly
---

A command-line program (named `cli`) that runs either as a server or a client `cli` is provided.

To run the command as a client, specify the peer hostname and port number as the arguments.

```
% ./cli host port
```

To run the command as a server, specify the files that contain the certificate and private key, as well as the hostname and the port number to which the server should bind.

```
% ./cli -c server.crt -k server.key 0.0.0.0 4433
```

For more options, please refer to `./cli --help`.
