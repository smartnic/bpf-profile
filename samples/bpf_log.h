#ifndef BPF_LOG_H_
#define BPF_LOG_H_

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DISABLED (0)
#define ERR (1)
#define WARNING (2)
#define NOTICE (3)
#define INFO (4)
#define DEBUG (5)

#define LOG_LEVEL ERR

#define bpf_log_err(...) (LOG_LEVEL< ERR ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_warning(...) (LOG_LEVEL< WARNING ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_notice(...) (LOG_LEVEL< NOTICE ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_info(...) (LOG_LEVEL< INFO ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_debug(...) (LOG_LEVEL< DEBUG ? (0) : bpf_printk(__VA_ARGS__))

#endif // BPF_LOG_H_
