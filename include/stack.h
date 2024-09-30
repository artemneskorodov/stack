#ifndef STACK_H
#define STACK_H

#include <stdio.h>
#include <stdint.h>

#define CANARY_PROTECTION
#define HASH_PROTECTION
#define WRITE_DUMP

#ifdef CANARY_PROTECTION
#define STACK_CANARY_ON(...) __VA_ARGS__
#else
#define STACK_CANARY_ON(...)
#endif

#ifdef HASH_PROTECTION
#define STACK_HASH_ON(...) __VA_ARGS__
#else
#define STACK_HASH_ON(...)
#endif

#ifdef WRITE_DUMP
#define DUMP_INIT(__var_name, __print_function, __dump_file_name) __FILE__,        \
                                                                  __LINE__,        \
                                                                  #__var_name,     \
                                                                  __FUNCTION__,    \
                                                                  __print_function,\
                                                                  __dump_file_name,

#define STACK_WRITE_DUMP_ON(...) __VA_ARGS__
#else
#define DUMP_INIT(__var_name, __print_function, __dump_file_name)
#define STACK_WRITE_DUMP_ON(...)
#endif

struct stack_t {
        STACK_CANARY_ON(uint64_t    canary_left           );
          STACK_HASH_ON(size_t      structure_hash        );
          STACK_HASH_ON(size_t      data_hash             );
        STACK_CANARY_ON(uint64_t *  data_canary_left      );
        STACK_CANARY_ON(uint64_t *  data_canary_right     );
        STACK_CANARY_ON(size_t      actual_data_size      );
    STACK_WRITE_DUMP_ON(const char *initialized_file      );
    STACK_WRITE_DUMP_ON(const char *variable_name         );
    STACK_WRITE_DUMP_ON(size_t      line                  );
    STACK_WRITE_DUMP_ON(const char *initialized_func      );
    STACK_WRITE_DUMP_ON(const char *dump_file_name        );
    STACK_WRITE_DUMP_ON(FILE *      dump_file             );
    STACK_WRITE_DUMP_ON(int       (*print)(FILE *, void *));
                        void *      data                   ;
                        size_t      size                   ;
                        size_t      element_size           ;
                        size_t      capacity               ;
                        size_t      init_capacity          ;
        STACK_CANARY_ON(uint64_t    canary_right          );
};

enum stack_error_t {
    STACK_SUCCESS          = 0 ,
    STACK_UNEXPECTED_ERROR = 1 ,
    STACK_MEMORY_ERROR     = 2 ,
    STACK_DUMP_ERROR       = 3 ,
    STACK_NULL             = 4 ,
    STACK_NULL_DATA        = 5 ,
    STACK_DOUBLE_INIT      = 6 ,
    STACK_EMPTY            = 7 ,
    STACK_INCORRECT_SIZE   = 8 ,
    STACK_MEMORY_ATTACK    = 9 ,
    STACK_INVALID_CAPACITY = 10,
};

stack_error_t stack_init(STACK_WRITE_DUMP_ON(const char *initialized_file,
                                             size_t      line,
                                             const char *variable_name,
                                             const char *function_name,
                                             int       (*print)(FILE *,void *),
                                             const char *dump_file_name,)
                         stack_t *   stack,
                         size_t      init_capacity,
                         size_t      element_size);
stack_error_t stack_push   (stack_t *stack,
                            void *   elem);
stack_error_t stack_pop    (stack_t *stack,
                            void *   output);
stack_error_t stack_destroy(stack_t *stack);

#endif
