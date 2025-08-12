#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe6edc48, "filp_open" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x88ccf8b7, "find_pid_ns" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0x86db7b35, "proc_create" },
	{ 0xb0e602eb, "memmove" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x48d88a2c, "__SCT__preempt_schedule" },
	{ 0x9662a5c1, "task_active_pid_ns" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0xae04012c, "__vmalloc" },
	{ 0xdf437eec, "seq_lseek" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x7573e830, "pskb_expand_head" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xa916b694, "strnlen" },
	{ 0xd4884ff4, "init_task" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0x6da03e57, "pid_task" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x6e0999e8, "kfree_skb_reason" },
	{ 0x670ecece, "__x86_indirect_thunk_rbx" },
	{ 0x5a921311, "strncmp" },
	{ 0x9166fada, "strncpy" },
	{ 0x449ad0a7, "memcmp" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x210a5321, "current_task" },
	{ 0x32b2572e, "skb_checksum" },
	{ 0xfb578fc5, "memset" },
	{ 0xd8668728, "param_ops_charp" },
	{ 0x6bd3d45f, "kernel_read" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0xd19c9a9f, "__pskb_pull_tail" },
	{ 0x26b78edc, "skb_trim" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x7e5f089c, "pv_ops" },
	{ 0x675d5d51, "seq_read" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x4629334c, "__preempt_count" },
	{ 0x999e8297, "vfree" },
	{ 0x72ca4f49, "filp_close" },
	{ 0xdeececbf, "remove_proc_entry" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x2beaa996, "seq_puts" },
	{ 0x7bd3dfe8, "single_release" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0x1ddfad9a, "send_sig" },
	{ 0x362f9a8, "__x86_indirect_thunk_r12" },
	{ 0xca078420, "kmalloc_trace" },
	{ 0x754d539c, "strlen" },
	{ 0x3f83077c, "tcp_prot" },
	{ 0x8a8cd00a, "single_open" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x8d5931c0, "kmalloc_caches" },
	{ 0xedb5d0d0, "kernel_write" },
	{ 0x2d3385d3, "system_wq" },
	{ 0x82583a65, "module_layout" },
};

MODULE_INFO(depends, "");

