#!/bin/python3
#this should print every time write is called
from bcc import BPF
from bcc.utils import printb
import os


# BPF program
program = """

#include <linux/sched.h>

//define struct with data to pass to python
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 timestamp;
};
//pass event info though events
BPF_PERF_OUTPUT(events);

int write_func(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.timestamp = bpf_ktime_get_ns();

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# attach bpf program to wirte syscall
b = BPF(text=program)
b.attach_kprobe(event="vfs_write", fn_name="write_func")

print("Tracing sys_sync()... Ctrl-C to end")

# dictionary keeps track of when processes have written
process_ts_list = {}
process_info = []

write_limit = 100
time_limit = 2000000000

def print_event(cpu, data, size):
    event = b["events"].event(data)
    # check if process has already written previously
    if event.pid not in process_ts_list:
        process_ts_list[event.pid] = []
        process_ts_list[event.pid].append(event.timestamp)
        process_info.append((event.pid, str(event.comm)))
    else:
    # check oldest timestamp(s) and remove after a fixed parameter
        all_olds_removed = False
        while not all_olds_removed:
            if event.timestamp - process_ts_list[event.pid][0] >  time_limit:
                process_ts_list[event.pid].pop(0)
                if len(process_ts_list[event.pid]) == 0:
                    all_olds_removed = True
            else:
                all_olds_removed = True
        process_ts_list[event.pid].append(event.timestamp)
    # check if the limit to cause a flag is reached:
    return 0

# output
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except ValueError:
        continue
    except KeyboardInterrupt:
        for p in process_info:
            # TODO: format output better
            print("pid: " + str(p[0]) + " name: " + p[1] + " num of processes: " + str(len(process_ts_list[p[0]])))
        exit()
