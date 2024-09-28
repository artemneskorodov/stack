#ifndef STACK_H
#define STACK_H

#include <stdio.h>

#ifndef NDEBUG
#define ON_DEBUG(...) __VA_ARGS__
#define DEBUG_INIT(__var_name, __print_function, __dump_file_name) ,__FILE__        ,\
                                                                    __LINE__        ,\
                                                                    #__var_name     ,\
                                                                    __FUNCTION__    ,\
                                                                    __print_function,\
                                                                    __dump_file_name

#else
#define ON_DEBUG(...)
#define DEBUG_INIT(__var_name, __print_function, __dump_file_name)
#endif

struct stack_t {
    ON_DEBUG(size_t      structure_hash        );
    ON_DEBUG(size_t      data_hash             );
    ON_DEBUG(size_t      canary_left           );
    ON_DEBUG(size_t *    data_canary_left      );
    ON_DEBUG(size_t *    data_canary_right     );
    ON_DEBUG(const char *initialized_file      );
    ON_DEBUG(const char *variable_name         );
    ON_DEBUG(size_t      line                  );
    ON_DEBUG(const char *initialized_func      );
    ON_DEBUG(const char *dump_file_name        );
    ON_DEBUG(FILE *      dump_file             );
    ON_DEBUG(int       (*print)(FILE *, void *));
             void *      data                   ;
             size_t      size                   ;
             size_t      element_size           ;
             size_t      capacity               ;
             size_t      init_capacity          ;
    ON_DEBUG(size_t      canary_right          );
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

stack_error_t stack_init(stack_t *   stack,
                         size_t      init_capacity,
                         size_t      element_size
               ON_DEBUG(,const char *initialized_file     )
               ON_DEBUG(,size_t      line                 )
               ON_DEBUG(,const char *variable_name        )
               ON_DEBUG(,const char *function_name        )
               ON_DEBUG(,int       (*print)(FILE *,void *))
               ON_DEBUG(,const char *dump_file_name       ));

stack_error_t stack_push(stack_t *stack,
                         void *   elem);

stack_error_t stack_pop (stack_t *stack,
                         void *   output);

stack_error_t stack_destroy(stack_t *stack);

#endif
