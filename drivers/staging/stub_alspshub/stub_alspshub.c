#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linastorvaldz");
MODULE_DESCRIPTION("Stub alspshub");

// init
static int __init stub_alspshub_init(void)
{
    pr_info("stub_alspshub: init.\n");
    return 0;
}

// --- stub functions ---

// stub: ps_enable_register_notifier
void ps_enable_register_notifier(void)
{
    pr_info("stub_alspshub: ps_enable_register_notifier called\n");
}
EXPORT_SYMBOL_GPL(ps_enable_register_notifier);

// stub: ps_register_recive_touch_event_callback
void ps_register_recive_touch_event_callback(void)
{
    pr_info("stub_alspshub: ps_register_recive_touch_event_callback called\n");
}
EXPORT_SYMBOL_GPL(ps_register_recive_touch_event_callback);

// stub: ps_tpd
void ps_tpd(void)
{
    pr_info("stub_alspshub: ps_tpd called\n");
}
EXPORT_SYMBOL_GPL(ps_tpd);

// exit
static void __exit stub_alspshub_exit(void)
{
    pr_info("stub_alspshub: exit.\n");
}

module_init(stub_alspshub_init);
module_exit(stub_alspshub_exit);
