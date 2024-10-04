#include "stack.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef NDEBUG
int print_func(FILE *file, void *elem);
int print_func(FILE *file, void *elem) {
    return fprintf(file, "%llx", *(uint64_t *)elem);
}

#endif

int main(void) {
    stack_t *stack = stack_init(DUMP_INIT("stack.log", stack, print_func) 4, sizeof(double));

    uint64_t arr[64] = {};
    for(size_t i = 0; i < 64; i++) {
        arr[i] = (uint64_t)i;
        stack_error_t err = stack_push(&stack, arr + i);
        if(err != STACK_SUCCESS) {
            printf("err = %d\n", err);
            stack_destroy(&stack);
            return 0;
        }
        printf("push %llu\n", i);
    }

    for(size_t i = 0; i < 61; i++) {
        uint64_t x = 0;
        stack_error_t err = stack_pop(&stack, &x);
        if(err != STACK_SUCCESS) {
            printf("err = %d\n", err);
            stack_destroy(&stack);
            return 0;
        }
        printf("pop %llu, elem = %llu\n", i, x);
    }
    for(size_t i = 0; i < 64; i++) {
        arr[i] = (uint64_t)i;
        stack_error_t err = stack_push(&stack, arr + i);
        if(err != STACK_SUCCESS) {
            printf("err = %d\n", err);
            stack_destroy(&stack);
            return 0;
        }
        printf("push %llu\n", i);
    }
    for(size_t i = 0; i < 67; i++) {
        uint64_t x = 0;
        stack_error_t err = stack_pop(&stack, &x);
        if(err != STACK_SUCCESS) {
            printf("err = %d\n", err);
            stack_destroy(&stack);
            return 0;
        }
        printf("pop %llu, elem = %llu\n", i, x);
    }

    printf("end\n");

    for(size_t i = 0; i < 200 / 8; i++) {
        printf("stack[0x%llx] = 0x%llx\n", (uint64_t *)stack + i, *((uint64_t *)stack + i));
    }

    stack_destroy(&stack);
    return 0;
}

