#ifndef STACK_H
#define STACK_H

#include <stdio.h>

typedef double stack_elem_t;

struct stack_t {
    stack_elem_t *data     ;
    size_t        size     ;
    size_t        capacity ;
    FILE *        dump_file;
};

enum stack_error_t {
    STACK_SUCCESS          = 0,
    STACK_UNEXPECTED_ERROR = 1,
    STACK_MEMORY_ERROR     = 2,
    STACK_DUMP_ERROR       = 3,
    STACK_NULL             = 4,
    STACK_NULL_DATA        = 5,
    STACK_DOUBLE_INIT      = 6,
    STACK_EMPTY            = 7,
};

stack_error_t stack_init(stack_t *stack,
                         size_t   init_capacity);

stack_error_t stack_push(stack_t *    stack,
                         stack_elem_t elem);

stack_error_t stack_pop (stack_t *     stack,
                         stack_elem_t *output);

stack_error_t stack_destroy(stack_t *stack);

#endif
