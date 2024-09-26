#ifndef MEMORY_H
#define MEMORY_H

#include <stdlib.h>

void *recalloc(void * memory_cell,
               size_t old_size,
               size_t new_size,
               size_t element_size);

#endif
