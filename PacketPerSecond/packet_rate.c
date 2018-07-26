
 #include <linux/kthread.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>

#ifndef SLEEP_MILLI_SEC
#define SLEEP_MILLI_SEC(nMilliSec)\
do { \
long timeout = (nMilliSec) * HZ / 1000; \
while(timeout > 0) \
{ \
timeout = schedule_timeout(timeout); \
} \
}while(0);
#endif


unsigned int count =0; // number of packets

unsigned int nf_count_packet_hook( unsigned int hooknum, struct sk_buff *skb, //hook function
        const struct net_device *in, const struct net_device *out,
        int(*okfn)( struct sk_buff * ) )
        {
            if(skb)
            {
                count = count+1;
                //printk(KERN_INFO "count=%d" ,count);
            }
            return NF_ACCEPT;
        }

static struct nf_hook_ops myhook_ops __read_mostly =  //nf_hook_ops
{
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_IN,
    .hook = (nf_hookfn *)nf_count_packet_hook,
};


static struct task_struct * rThread = NULL;   // thread

static int printRate(void *data )
{
    while(!kthread_should_stop())
    {
        int beforCount = count;
        SLEEP_MILLI_SEC(1000);
        int afterCount = count;
        printk(KERN_ALERT "rate=%d", afterCount - beforCount );
    }
    
    return 0;
}
static int __init start(void)
{
    nf_register_hook(&myhook_ops);
    rThread = kthread_run(printRate,NULL,"rthread");
    return 0;
}
static void __exit finish(void)
{
    if(rThread)
    {
        printk("stop rate module\n");
        nf_unregister_hook(&myhook_ops);
        kthread_stop(rThread);
    }
}
module_init(start);
module_exit(finish);
