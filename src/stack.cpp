#include <stdlib.h>
#include <string.h>
#include "stack.h"
#include "memory.h"

#define STACK_ASSERT(stack) {                            \
    stack_error_t stack_error_state = stack_error(stack);\
    if(stack_error_state != STACK_SUCCESS) {             \
        stack_dump(stack, __FILE__, __LINE__);           \
        stack_destroy(stack);                            \
        return stack_error_state;                        \
    }                                                    \
}                                                        \

enum stack_operation_t {
    OPERATION_PUSH,
    OPERATION_POP ,
};

const char *DUMP_FILE_NAME = "stack.dmp";

static stack_error_t stack_check_size(stack_t *         stack,
                                      stack_operation_t operation);

static stack_error_t stack_error(stack_t *stack);

static stack_error_t stack_dump(stack_t *   stack,
                                const char *filename,
                                size_t      line);

stack_error_t stack_init(stack_t *stack,
                         size_t   init_capacity) {
    if(stack == NULL)
        return STACK_NULL;

    if(stack->data != NULL) {
        stack_destroy(stack);
        return STACK_DOUBLE_INIT;
    }
    stack->data = (stack_elem_t *)calloc(init_capacity,
                                         sizeof(stack_elem_t));
    if(stack->data == NULL)
        return STACK_MEMORY_ERROR;

    stack->dump_file = fopen(DUMP_FILE_NAME, "wb");
    if(stack->dump_file == NULL) {
        stack_destroy(stack);
        return STACK_DUMP_ERROR;
    }

    stack->capacity = init_capacity;
    stack->size = 0;
    return STACK_SUCCESS;
}

stack_error_t stack_push(stack_t *    stack,
                         stack_elem_t elem) {
    STACK_ASSERT(stack);

    stack_error_t check_size_state = stack_check_size(stack, OPERATION_PUSH);
    if(check_size_state != STACK_SUCCESS) {
        stack_destroy(stack);
        return check_size_state;
    }

    stack->data[stack->size] = elem;
    stack->size++;
    return STACK_SUCCESS;
}

stack_error_t stack_pop(stack_t *     stack,
                        stack_elem_t *output) {
    STACK_ASSERT(stack);
    stack_error_t check_size_state = stack_check_size(stack, OPERATION_POP);
    if(check_size_state != STACK_SUCCESS) {
        stack_destroy(stack);
        return check_size_state;
    }

    if(stack->size == 0)
        return STACK_EMPTY;

    stack->size--;
    *output = stack->data[stack->size];
    stack->data[stack->size] = 0;
    return STACK_SUCCESS;
}

stack_error_t stack_destroy(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    if(stack->data != NULL)
        free(stack->data);

    memset(stack, 0, sizeof(stack_t));
    return STACK_SUCCESS;
}

stack_error_t stack_check_size(stack_t *         stack,
                               stack_operation_t operation) {
    size_t new_capacity = 0;
    switch(operation) {
        case OPERATION_PUSH: {
            if(stack->size < stack->capacity)
                return STACK_SUCCESS;
            new_capacity = stack->capacity * 2;
            break;
        }
        case OPERATION_POP:  {
            if(stack->size * 2 >= stack->capacity)
                return STACK_SUCCESS;
            new_capacity = stack->capacity / 2;
            break;
        }
        default:             {
            return STACK_UNEXPECTED_ERROR;
        }
    }
    stack_elem_t *new_memory_cell = (stack_elem_t *)recalloc(stack->data,
                                                             stack->capacity,
                                                             new_capacity,
                                                             sizeof(stack_elem_t));
    if(new_memory_cell == NULL && new_capacity != 0)
        return STACK_MEMORY_ERROR;

    stack->data     = new_memory_cell;
    stack->capacity = new_capacity;
    return STACK_SUCCESS;
}

stack_error_t stack_error(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    if((stack->data == NULL) != (stack->capacity == 0))
        return STACK_NULL_DATA;

    return STACK_SUCCESS;
}

stack_error_t stack_dump(stack_t *   stack,
                         const char *filename,
                         size_t      line) {
    if(fprintf(stack->dump_file,
               "================================================\r\n"
               "This dump was called from line %llu of file '%s'\r\n"
               "stack =           %p\r\n"
               "stack->data =     %p\r\n"
               "stack->size =     %llu\r\n"
               "stack->capacity = %llu\r\n"
               "Stack elements:\r\n",
               line, filename, stack, stack->data, stack->size, stack->capacity) < 0)
        return STACK_DUMP_ERROR;

    for(size_t i = 0; i < stack->size; i++)
        if(fprintf(stack->dump_file, "%lf\n", stack->data[i]) < 0)
            return STACK_DUMP_ERROR;

    if(fprintf(stack->dump_file,
               "================================================\r\n\r\n") < 0)
        return STACK_DUMP_ERROR;

    return STACK_SUCCESS;
}
