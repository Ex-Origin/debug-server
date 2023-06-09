
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
3. Change the following arguments to your target in `debug-server.c`, followed by compiling the code and situating it within your intended context. Proceed to execute the `debug-server`.

    ```c
    char *service_args[]    = {"/bin/sh", NULL};
    ```

4. Use `gdbpwn.py` to connect to the target IP.
5. Use `exp.py` to connect to the target IP to start the target and send `attach instruction`.

## Features

* Cross-platform
* More automatic
