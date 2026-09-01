/*
 * ovs_cpu_full.bpf.c - BPF program for measuring CPU time per OVS slice
 *
 * Measures CPU time through all packet processing phases:
 *   - ovs_dp_process_packet (OVS datapath)
 *   - veth_xmit (veth transfer)
 *   - netif_receive_skb (network stack receive)
 *   - dev_queue_xmit (device transmit)
 *
 * Based on original ovs_ifindex_cpu.bpf.c
 */

#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

struct start_t {
    u64 ts;
    u32 ifindex;
};

struct key_t {
    u32 ifindex;
};

// Maps for storing start timestamp and ifindex
BPF_HASH(start_ovs, u64, struct start_t);
BPF_HASH(start_veth, u64, struct start_t);
BPF_HASH(start_netif, u64, struct start_t);
BPF_HASH(start_xmit, u64, struct start_t);

// Maps for accumulated CPU time per ifindex
BPF_HASH(cpu_time_ovs, struct key_t, u64);
BPF_HASH(cpu_time_veth, struct key_t, u64);
BPF_HASH(cpu_time_netif, struct key_t, u64);
BPF_HASH(cpu_time_xmit, struct key_t, u64);
BPF_HASH(cpu_time_total, struct key_t, u64);

// ============== OVS datapath ==============
// ovs_dp_process_packet takes struct datapath *dp, struct sk_buff *skb, ...
// skb is the second parameter

int trace_ovs_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);  // skb is PARM2
    struct net_device *dev = NULL;
    u32 ifindex = 0;
    struct start_t val = {};

    if (skb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
        if (dev)
            bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    val.ts = bpf_ktime_get_ns();
    val.ifindex = ifindex;

    start_ovs.update(&pid_tgid, &val);
    return 0;
}

int trace_ovs_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *st = start_ovs.lookup(&pid_tgid);
    if (!st)
        return 0;

    u64 delta = bpf_ktime_get_ns() - st->ts;

    struct key_t key = {.ifindex = st->ifindex};

    u64 *total = cpu_time_ovs.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_ovs.update(&key, &delta);

    total = cpu_time_total.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_total.update(&key, &delta);

    start_ovs.delete(&pid_tgid);
    return 0;
}

// ============== Veth transfer ==============

int trace_veth_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct net_device *dev = NULL;
    u32 ifindex = 0;
    struct start_t val = {};

    if (skb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
        if (dev)
            bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    val.ts = bpf_ktime_get_ns();
    val.ifindex = ifindex;

    start_veth.update(&pid_tgid, &val);
    return 0;
}

int trace_veth_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *st = start_veth.lookup(&pid_tgid);
    if (!st)
        return 0;

    u64 delta = bpf_ktime_get_ns() - st->ts;

    struct key_t key = {.ifindex = st->ifindex};

    u64 *total = cpu_time_veth.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_veth.update(&key, &delta);

    total = cpu_time_total.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_total.update(&key, &delta);

    start_veth.delete(&pid_tgid);
    return 0;
}

// ============== Netif receive ==============

int trace_netif_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct net_device *dev = NULL;
    u32 ifindex = 0;
    struct start_t val = {};

    if (skb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
        if (dev)
            bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    val.ts = bpf_ktime_get_ns();
    val.ifindex = ifindex;

    start_netif.update(&pid_tgid, &val);
    return 0;
}

int trace_netif_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *st = start_netif.lookup(&pid_tgid);
    if (!st)
        return 0;

    u64 delta = bpf_ktime_get_ns() - st->ts;

    struct key_t key = {.ifindex = st->ifindex};

    u64 *total = cpu_time_netif.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_netif.update(&key, &delta);

    total = cpu_time_total.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_total.update(&key, &delta);

    start_netif.delete(&pid_tgid);
    return 0;
}

// ============== Dev queue xmit ==============

int trace_xmit_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct net_device *dev = NULL;
    u32 ifindex = 0;
    struct start_t val = {};

    if (skb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
        if (dev)
            bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    val.ts = bpf_ktime_get_ns();
    val.ifindex = ifindex;

    start_xmit.update(&pid_tgid, &val);
    return 0;
}

int trace_xmit_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *st = start_xmit.lookup(&pid_tgid);
    if (!st)
        return 0;

    u64 delta = bpf_ktime_get_ns() - st->ts;

    struct key_t key = {.ifindex = st->ifindex};

    u64 *total = cpu_time_xmit.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_xmit.update(&key, &delta);

    total = cpu_time_total.lookup(&key);
    if (total)
        *total += delta;
    else
        cpu_time_total.update(&key, &delta);

    start_xmit.delete(&pid_tgid);
    return 0;
}
