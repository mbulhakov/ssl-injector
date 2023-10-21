
# ssl-injector

[eBPF](https://ebpf.io/) monitor application using [aya.rs](https://github.com/aya-rs/aya) to capture SSL_write/SSL_read calls using uprobe/uretprobe. Logs captured content both in the console and in a temporary folder.

## Prerequisites  

1. Linux or Mac (tested on M2, but Intel chips should work as well)
2. Docker


## Build

Only Docker image build is supported, but one can repeat it locally using commands from the image.

To ease the burden of possible different architectures (hi Apple silicon) use the following script to build the image:

```bash
./build_docker.sh
``` 

## Run


```bash
./run_docker.sh
```
