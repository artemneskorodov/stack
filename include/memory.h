#ifndef MEMORY_H
#define MEMORY_H

#include <stdio.h>
#include <stdlib.h>

void *_recalloc         (void * memory_cell,
                         size_t old_size,
                         size_t new_size,
                         size_t element_size);
void *_calloc           (size_t number,
                         size_t element_size);
void _free              (void *memory_cell);
void _memory_destroy_log(void);

#endif
