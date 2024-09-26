#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"

void *recalloc(void * memory_cell,
               size_t old_size,
               size_t new_size,
               size_t element_size) {
    void *new_memory_cell = realloc(memory_cell,
                                    new_size * element_size);
    if(new_memory_cell == NULL)
        return NULL;

    if(new_size > old_size)
        memset((char *)new_memory_cell + old_size * element_size,
               0,
               (new_size - old_size) * element_size);

    return new_memory_cell;
}
