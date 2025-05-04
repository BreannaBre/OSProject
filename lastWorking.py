#!/bin/python3
from bcc import BPF
from bcc.utils import printb
import os
import sys
import time

# CHANGE THESE PARAMETERS to set when a process should be flagged
# write_limit is the max amount of writes a process can have in a set amount of time
write_limit = 100
# time_limit is the length of time the writes must occur in for it to be flagged
# ex: if 100 writes occur within 2 seconds, flag the program
time_limit_seconds = 2

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
BPF_RINGBUF_OUTPUT(events, 8);

int write_func(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.timestamp = bpf_ktime_get_ns();

    events.ringbuf_output(&data, sizeof(data), 0);

    return 0;
}
"""

# attach bpf program to wirte syscall
b = BPF(text=program)
b.attach_kprobe(event="vfs_write", fn_name="write_func")

print("Tracing write_sync()... Ctrl-C to end")

# keep track of timpstamps when processes wrote, additional info of process (such as name), and a count of times its been flagged
process_ts_list = {}
process_info = []
offending_processes = {}

# function to check and flag after inital removal/appending has occured for process
def check_flagging(pid, comm):
    if len(process_ts_list[pid]) > write_limit:
        if pid not in offending_processes:
            offending_processes[pid] = 1
        else:
            offending_processes[pid] += 1
        # reset list and log if it occurs again
        process_ts_list[pid] = []
        print("Offending process pid: " + str(pid) + " name: " + str(comm))

# function that handles data when a write occurs
def document_event(cpu, data, size):
    event = b["events"].event(data)
    # check if process has already written previously
    if event.pid not in process_ts_list:
        process_ts_list[event.pid] = []
        process_ts_list[event.pid].append(event.timestamp)
        process_info.append((event.pid, str(event.comm.decode())))
    else:
    # check oldest timestamp(s) and remove after a fixed parameter
        all_olds_removed = False
        while not all_olds_removed:
            if len(process_ts_list[event.pid]) == 0:
                    all_olds_removed = True
            elif event.timestamp - process_ts_list[event.pid][0] >  (time_limit_seconds * 1000000000):
                process_ts_list[event.pid].pop(0)
            else:
                all_olds_removed = True
        process_ts_list[event.pid].append(event.timestamp)
    check_flagging(event.pid, event.comm.decode())

    return 0

# This is the *main* part of the program
b["events"].open_ring_buffer(document_event)
while True:
    try:
        b.ring_buffer_poll()
        time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nSummary of Flagged Processes:")
        printb(b"%-8s %-20s %-5s" % (b"PID", b"NAME", b"NUM TIMES FLAGGGED"))
        for p in process_info:
            if p[0] in offending_processes:
                print("%-8d %-20s %-5d" % (p[0], p[1], offending_processes[p[0]]))
        sys.exit()

