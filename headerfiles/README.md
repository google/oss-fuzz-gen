# headerfiles
Header file inference tool for LLM-based fuzz driver generation to OSS-Fuzz projects. Currently, this project is for [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) usage purpose and will be more general later.

# API

There are three APIs:

```
headerfiles.api

- is_supported_proj
  - Usage: Check if a projection is supported by the API.
  - Return value: True if the projection is supported, False otherwise.

- get_proj_headers
  - Usage: Get the inferred headers for a specific project.
  - Return value: A list of inferred headers for the project, their orders also matter.

- get_build_script
  - Usage: Get the build script for a specific project supported in OSS-FUZZ.
  - Return value: The build script for the project.

```

# Support List (50 projects till now)

- [x] avahi
- [x] bind9
- [x] bluez
- [x] brotli
- [x] capstone
- [x] coturn
- [x] croaring
- [x] igraph
- [x] kamailio
- [x] krb5
- [x] lcms
- [x] libbpf
- [x] libcoap
- [x] libevent
- [x] libfido2
- [x] libical
- [x] libjpeg-turbo
- [x] libpcap
- [x] librdkafka
- [x] libsndfile
- [x] libsodium
- [x] libssh
- [x] libssh2
- [x] libtpms
- [x] libusb
- [x] libvnc
- [x] libxls
- [x] libyang
- [x] lwan
- [x] mbedtls
- [x] mdbtools
- [x] minizip
- [x] ndpi
- [x] njs
- [x] oniguruma
- [x] openexr
- [x] opusfile
- [x] picotls
- [x] pjsip
- [x] proftpd
- [x] pupnp
- [x] sleuthkit
- [x] tidy-html5
- [x] unicorn
- [x] unit
- [x] utf8proc
- [x] vlc
- [x] w3m
- [x] wasm3
- [x] zydis


# Test

```bash
python3 -m tests.test_api
```
