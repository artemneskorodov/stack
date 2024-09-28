#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "memory.h"

enum memory_operation_t {
    MEMORY_ALLOCATION  ,
    MEMORY_REALLOCATION,
    MEMORY_FREE        ,
    MEMORY_LOG_OPEN    ,
    MEMORY_LOG_CLOSE   ,
};

#ifndef NDEBUG

static FILE *log_file = NULL;
void memory_log(memory_operation_t operation, ...);
static const char *LOG_FILE_NAME = "memory.log";
#define MEMORY_LOG(operation, ...) memory_log(operation, __VA_ARGS__)

#else

#define MEMORY_LOG(operation, ...) ((void)0);

#endif

void *_recalloc(void * memory_cell ,
                size_t old_size    ,
                size_t new_size    ,
                size_t element_size) {
    void *new_memory_cell = realloc(memory_cell            ,
                                    new_size * element_size);
    MEMORY_LOG(MEMORY_REALLOCATION, memory_cell, old_size, new_memory_cell, new_size);
    if(new_memory_cell == NULL)
        return NULL;

    if(new_size > old_size)
        memset((char *)new_memory_cell + old_size * element_size,
               0,
               (new_size - old_size) * element_size);

    return new_memory_cell;
}

void *_calloc(size_t number      ,
              size_t element_size) {
    void *memory_cell = calloc(number, element_size);
    MEMORY_LOG(MEMORY_ALLOCATION, memory_cell, number, element_size);
    return memory_cell;
}

void _free(void *memory_cell) {
    MEMORY_LOG(MEMORY_FREE, memory_cell);
    free(memory_cell);
}

#ifndef NDEBUG
void memory_log(memory_operation_t operation, ...) {
    if(log_file == NULL) {
        log_file = fopen(LOG_FILE_NAME, "wb");
        if(log_file == NULL) {
            printf("Error opening memory dump file.\n");
            return ;
        }
        MEMORY_LOG(MEMORY_LOG_OPEN, NULL);
    }

    va_list args;
    va_start(args, operation);

    switch(operation) {
        case MEMORY_ALLOCATION:   {
            const void *allocated = va_arg(args, void *);
            size_t number = va_arg(args, size_t);
            size_t element_size = va_arg(args, size_t);

            fprintf(log_file,
                    "=====================================\r\n"
                    "ALLOCATION\r\n"
                    "Memory:       0x%p\r\n"
                    "Number:       %llu\r\n"
                    "Element size: %llu\r\n"
                    "=====================================\r\n\r\n",
                    allocated,
                    number,
                    element_size);
            break;
        }
        case MEMORY_REALLOCATION: {
            const void *old_memory = va_arg(args, void *);
            size_t old_size = va_arg(args, size_t);
            const void *new_memory = va_arg(args, void *);
            size_t new_size = va_arg(args, size_t);

            fprintf(log_file,
                    "=====================================\r\n"
                    "REALLOCATION\r\n"
                    "Old memory:   0x%p\r\n"
                    "Old size:     %llu\r\n"
                    "New memory:   0x%p\r\n"
                    "New size:     %llu\r\n"
                    "=====================================\r\n\r\n",
                    old_memory,
                    old_size,
                    new_memory,
                    new_size);
            break;
        }
        case MEMORY_FREE:         {
            const void *memory = va_arg(args, void *);
            fprintf(log_file,
                    "=====================================\r\n"
                    "FREE\r\n"
                    "Memory:       0x%p\r\n"
                    "=====================================\r\n\r\n",
                    memory);
            break;
        }
        case MEMORY_LOG_OPEN:     {
            fprintf(log_file,
                    "=====================================\r\n"
                    "LOG_FILE_OPEN\r\n"
                    "=====================================\r\n\r\n");
            break;
        }
        case MEMORY_LOG_CLOSE:    {
            fprintf(log_file,
                    "=====================================\r\n"
                    "LOG_FILE_CLOSE\r\n"
                    "=====================================\r\n\r\n");
            break;
        }
        default:                  {
            fprintf(log_file,
                    "=====================================\r\n"
                    "Incorrect log call\r\n"
                    "=====================================\r\n\r\n");
            break;
        }
    }
    va_end(args);
}
#endif

void _memory_destroy_log(void) {
    #ifndef NDEBUG
    MEMORY_LOG(MEMORY_LOG_CLOSE, NULL);
    fclose(log_file);
    #endif
}
