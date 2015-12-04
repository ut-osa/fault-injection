#ifndef _LINUX_SWIFI_H
#define _LINUX_SWIFI_H
#include <linux/types.h>
#include <asm/pgtable_types.h> /* pgprot_t */
#include <linux/swifi-user.h>

int swifi_set_target_name(char *target_name);
char *swifi_get_target_name(void);
long swifi_do_faults(struct swifi_fault_params *p);
void swifi_toggle_verbose(void);

int swifi_init(void);
void swifi_exit(void);

#endif // _LINUX_SWIFI_H
