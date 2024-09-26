#include "stack.h"

int main(void) {
    stack_t stack = {};
    stack_init(&stack, 2);
    for(int i = 0; i < 64; i++) {
        stack_push(&stack, i);
    }
    for(int i = 0; i < 64; i++) {
        double x = 0;
        stack_pop(&stack, &x);
        printf("%f\n", x);
    }
}
