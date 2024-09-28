#include "stack.h"

#ifndef NDEBUG
int print_func(FILE *file, void *elem);
int print_func(FILE *file, void *elem) {
    return fprintf(file, "%lf", *(double *)elem);
}
#endif

int main(void) {
    stack_t stack = {};
    printf("stack_init = %d\n", stack_init(&stack, 2, sizeof(double) DEBUG_INIT(stack, print_func, NULL)));
    printf("in = %llu\n", stack.init_capacity);
    double arr[64] = {};
    for(size_t i = 0; i < sizeof(arr) / sizeof(arr[0]); i++)
        arr[i] = (double)i;
    for(size_t i = 0; i < 64; i++) {
        printf("push %f = %d\n", arr[i], stack_push(&stack, arr + i));
    }
    *((double *)stack.data + 10) = 4;
    for(int i = 0; i < 2; i++) {
        double x = 0;
        stack_error_t state = stack_pop(&stack, &x);
        if(state != STACK_SUCCESS) {
            printf("err = %d\n", state);
            stack_destroy(&stack);
            return -1;
        }
        printf("pop = %d, elem = %f\n", state, x);
    }
    return 0;
    double ten = 10;
    printf("push10 = %d\n", stack_push(&stack, &ten));
    for(int i = 0; i < 35; i++) {
        double x = 0;
        stack_error_t state = stack_pop(&stack, &x);
        if(state != STACK_SUCCESS) {
            printf("err = %d\n", state);
            stack_destroy(&stack);
            return -1;
        }
        printf("pop = %d, elem = %f\n", state, x);
    }

    stack_destroy(&stack);
}

