# gtp5g - 5G compatible GTP kernel module
gtp5g is a customized Linux kernel module gtp5g to handle packet by PFCP IEs such as PDR and FAR.  
For detailed information, please reference to 3GPP specification TS 29.281 and TS 29.244.

## Notice
Due to the evolution of Linux kernel, this module would not work with any kernel version.  
Please run this module with kernel version `5.0.0-23-generic`.

## Usage
### Compile
```
make clean && make
```

### Install kernel module
Install the module to the system and load automatically at boot
```
sudo make install
```

### Remove kernel module
Remove the kernel module from the system
```
sudo make uninstall
```
