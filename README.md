# gtp5g - Linux kernel module 5G GTP-U
gtp5g is a customized Linux kernel module 5G GTP-U to handle packet
by PFCP IEs such as PDR and FAR. About more detail IEs, there are
more information in 3GPP TS 29.281 and 3GPP TS 29.244.

## Notice
Because of Linux kernel evolution, this module would not work at any version.
This module can work at version `5.0.0-23-generic`.

## Usage
### Compile
```
make clean && make
```

### Install kernel module
```
sudo make install
```

### Remove kernel module
```
sudo make uninstall
```
