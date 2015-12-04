/*
 * fault-model.c -- fault injection code for linux
 *
 * Copyright (c) 2014 <anonymous submission>
 *
 * Seperate out the swifi code.
 */

/*
 * Fault injector for testing the crash consistency of sego
 *
 * Adapted from the SWIFI tools used by Mike Swift to evaluate NOOKS
 * at the University of Washington and by Wee Teck Ng to evaluate the
 * RIO file cache at the University of Michigan
 *
 */

#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <asm/uaccess.h>

#include <linux/swifi.h>

MODULE_AUTHOR("Michael Z. Lee");
MODULE_LICENSE("GPL");

static long swifi_dev_ioctl_set_target(char __user *name)
{
	struct module *mod = NULL;
	unsigned long page = 0;
	long rc;

	page = __get_free_page(GFP_KERNEL);
	if (!page) {
		rc = -ENOMEM;
		goto out;
	}

	rc = strncpy_from_user((char *)page, name, PAGE_SIZE);
	if (rc < 0) {
		goto out_free;
	} else if (rc >= PAGE_SIZE) {
		rc = -ENAMETOOLONG;
		goto out_free;
	}

	if (strcmp((char *)page, "kernel") == 0 || \
	    strcmp((char *)page, "all") == 0) {
		/* Success */
		swifi_set_target_name((char *)page);
		goto out;
	}

	if (strcmp((char *)page, "range") == 0) {
		rc = copy_from_user((void *)page + 8, name + 8, 16);
		swifi_set_target_name((char *)page);
	}

	mutex_lock(&module_mutex);
	mod = find_module((char *)page);
	mutex_unlock(&module_mutex);
	if (mod) {
		/* Success */
		swifi_set_target_name((char *)page);
		goto out;
	}

out_free:
	free_page(page);
out:
	return rc;
}

static long swifi_dev_ioctl_do_faults(void __user *arg)
{
	struct swifi_fault_params params;
	copy_from_user(&params, arg, sizeof(struct swifi_fault_params));
	return swifi_do_faults(&params);
}

static long swifi_dev_ioctl_toggle_verbose(void)
{
	swifi_toggle_verbose();
	return 0;
}

static long swifi_dev_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg)
{
	long rc = -EINVAL;

	switch (ioctl) {
	case SWIFI_SET_TARGET:
		rc = swifi_dev_ioctl_set_target((char __user *)arg);
		break;
	case SWIFI_DO_FAULTS:
		rc = swifi_dev_ioctl_do_faults((void __user *)arg);
		break;
	case SWIFI_VERBOSE:
		rc = swifi_dev_ioctl_toggle_verbose();
		break;
	}
	return rc;
}

static const struct file_operations swifi_chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= swifi_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= swifi_dev_ioctl,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice swifi_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "swifi",
	.fops = &swifi_chardev_ops,
	.mode = S_IRUGO | S_IWUGO,
};

static void swifi_free(void)
{
	char *target_name = swifi_get_target_name();
	if (target_name)
		free_page((unsigned long)target_name);
}

int __init swifi_init(void)
{
	int rc = 0;
	printk(KERN_ERR "%s\n", __func__);
	rc = misc_register(&swifi_dev);
	if (rc) {
		printk(KERN_ERR "swifi: misc device register failed\n");
		swifi_free();
	}
	return rc;
}
module_init(swifi_init);

void __exit swifi_exit(void)
{
	misc_deregister(&swifi_dev);
	swifi_free();
	printk(KERN_ERR "%s\n", __func__);
}
module_exit(swifi_exit);
