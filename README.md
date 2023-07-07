
# Debug Server

A customized debug tool designing to automatic attach the target process in either remote or pwntools contexts.

![Architecture](architecture.png)

## Requirements

Please install the following package.

```shell
apt update
apt install -y gdbserver strace
```

## Usage

1. Add this directory to `$PATH`.
2. Run `gdbinit.py` in your intended workspace to initial environment.
3. Run `debug-server`

    ```
    Usage: debug-server [-hmsvn] [-e CMD] [-p CMD]

    General:
    -e CMD   service argv
    -p CMD   get pid by popen
    -h       print help message
    -m       enable multi-service
    -s       halt at entry point
    -v       show debug information
    -n       disable address space randomization
    ```

4. Use `gdbpwn.py` to connect to the target IP.
5. Use `exp.py` to connect to the target IP to start the target and send `attach instruction`.

## Features

* Cross-platform
* More automatic
* Streamline the debugging process for reverse engineering (Feature: HALT_AT_ENTRY_POINT)
