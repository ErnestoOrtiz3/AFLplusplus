# AFL++ eBPF Performance Statistics

## Requirements

To use eBPF-based performance statistics collection, your system must meet the following requirements:

1. Linux kernel version 4.15 or later
2. Root privileges or appropriate capabilities
3. Mounted BPF filesystem
4. Appropriate perf_event_paranoid settings

## Setting up permissions

### Option 1: Running with sudo
```bash
sudo afl-fuzz [options] /path/to/target
```

### Option 2: Setting capabilities
```bash
sudo setcap cap_bpf+ep $(which afl-fuzz)
sudo setcap cap_perfmon+ep $(which afl-fuzz)
```

### Option 3: Permanent system configuration
Add to /etc/sysctl.conf:
```bash
kernel.perf_event_paranoid=1
kernel.unprivileged_bpf_disabled=0
```

Then apply with:
```bash
sudo sysctl -p
```

Mount BPF filesystem:
```bash
sudo mount -t bpf bpf /sys/fs/bpf/
```

## Troubleshooting

If eBPF stats collection fails, AFL++ will automatically fall back to traditional statistics collection. Check the startup messages for specific error information and required actions.