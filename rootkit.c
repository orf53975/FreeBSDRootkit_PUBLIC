#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

static int load(struct module * module, int cmd, void * arg)
{
	int err = 0;

	switch(cmd)
	{
		case MOD_LOAD:
			uprintf("Hello world\n");
			break;
		case MOD_UNLOAD:
			uprintf("Goodbye world\n");
			break;
		default:
			err = EOPNOTSUPP;
			break;
	}

	return err;
}

static moduledata_t rootkit_mod =
{
	"rootkit",	/* module name */
	load,		/* event handler */
	NULL		/* extra data */
};

DECLARE_MODULE(rootkit, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
