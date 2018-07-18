#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>


unsigned int count =0;
unsigned int nf_count_packet_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)( struct sk_buff * ) )
        {
            count = count+1;
            printk(KERN_INFO "count=%d" ,count);
            return NF_ACCEPT;
        }

static struct nf_hook_ops myhook_ops __read_mostly = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_IN,
    .hook = (nf_hookfn *)nf_count_packet_hook,
};

static int __init rate_init(void)
{
    return nf_register_hook(&myhook_ops);
}

static void __exit rate_exit(void)
{
    nf_unregister_hook(&myhook_ops);
}


module_init(rate_init);
module_exit(rate_exit);


MODULE_LICENSE("GPL");
