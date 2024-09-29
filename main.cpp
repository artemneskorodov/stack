#include "stack.h"
#include <stdlib.h>
#include <string.h>

#ifndef NDEBUG
int print_func(FILE *file, void *elem);
int print_func(FILE *file, void *elem) {
    return fprintf(file, "%lf", *(double *)elem);
}

int pchar(FILE *file, void *elem) {
    return fputc(*(char *)elem, file);
}

#endif

int main(void) {
    stack_t st = {};
    stack_error_t err = STACK_SUCCESS;
    if(err = stack_init(&st, 1, sizeof(char) DUMP_INIT(st, pchar, NULL))) {
        printf("err = %d\n", err);
        return EXIT_FAILURE;
    }

    char data[] = "abcdefghijklmnoprst12345";
    for(size_t i = 0; i < strlen(data) - 3; i++) {
        if(err = stack_push(&st, data + i)) {
            printf("err = %d\n", err);
            return EXIT_FAILURE;
        }
    }
    *((char *)st.data) = 1;
    for(size_t i = 0; i < strlen(data); i++) {
        char c = 0;
        if(err = stack_pop(&st, &c)) {
            printf("err = %d\n", err);
            return EXIT_FAILURE;
        }
        printf("got %c\n", c);
    }
    stack_destroy(&st);
}

