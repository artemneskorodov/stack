#include <stdlib.h>
#include <string.h>
#include "stack.h"
#include "memory.h"

#define CANARY_PROTECTION
#define HASH_PROTECTION
#define WRITE_DUMP

//=============================================================================================================
//STACK CANARY PROTECTION
//=============================================================================================================
#ifdef  CANARY_PROTECTION
    static const size_t LEFT_HEX_SPEECH  = 0xBAAADDED;
    static const size_t RIGHT_HEX_SPEECH = 0xC000FFEE;

    #define STACK_UPDATE_CANARY(__stack_pointer) {                          \
        stack_error_t __canary_state = stack_update_canary(__stack_pointer);\
        if(__canary_state != STACK_SUCCESS)                                 \
            STACK_RETURN_ERROR(__stack_pointer, __canary_state);            \
    }

    static stack_error_t stack_update_canary   (stack_t *stack);
    static stack_error_t align_size            (stack_t *stack);
    static stack_error_t canary_verify         (stack_t *stack);
    static stack_error_t data_allocate_canary  (stack_t *stack);
    static stack_error_t data_reallocate_canary(stack_t *stack);
#else //STACK CANARY PROTECTION
    #define STACK_UPDATE_CANARY(__stack_pointer)
    static stack_error_t data_allocate_no_canary  (stack_t *stack);
    static stack_error_t data_reallocate_no_canary(stack_t *stack,
                                                   size_t   new_capacity);
#endif//STACK CANARY PROTECTION

//=============================================================================================================
//STACK HASH PROTECTION
//=============================================================================================================
#ifdef HASH_PROTECTION
    #define STACK_UPDATE_HASH(__stack_pointer) {                        \
        stack_error_t __hash_state = stack_update_hash(__stack_pointer);\
        if(__hash_state != STACK_SUCCESS)                               \
            STACK_RETURN_ERROR(__stack_pointer, __hash_state);          \
    }

    static stack_error_t stack_update_hash(stack_t *stack);
    static size_t        hash_function    (void *start, void *end);
    static stack_error_t stack_count_hash (stack_t *stack,
                                           size_t * data_hash,
                                           size_t * structure_hash);
    static stack_error_t hash_verify      (stack_t *stack);
#else //STACK HASH PROTECTION
    #define STACK_UPDATE_HASH(__stack_pointer)
#endif//STACK HASH PROTECTION

//=============================================================================================================
//WRITE DUMP MODE
//=============================================================================================================
#ifdef  WRITE_DUMP
    static const char *TEXT_STACK_SUCCESS          = "STACK_SUCCESS"         ;
    static const char *TEXT_STACK_UNEXPECTED_ERROR = "STACK_UNEXPECTED_ERROR";
    static const char *TEXT_STACK_MEMORY_ERROR     = "STACK_MEMORY_ERROR"    ;
    static const char *TEXT_STACK_DUMP_ERROR       = "STACK_DUMP_ERROR"      ;
    static const char *TEXT_STACK_NULL             = "STACK_NULL"            ;
    static const char *TEXT_STACK_NULL_DATA        = "STACK_NULL_DATA"       ;
    static const char *TEXT_STACK_DOUBLE_INIT      = "STACK_DOUBLE_INIT"     ;
    static const char *TEXT_STACK_EMPTY            = "STACK_EMPTY"           ;
    static const char *TEXT_STACK_INCORRECT_SIZE   = "STACK_INCORRECT_SIZE"  ;
    static const char *TEXT_STACK_MEMORY_ATTACK    = "STACK_MEMORY_ATTACK"   ;
    static const char *TEXT_STACK_INVALID_CAPACITY = "STACK_INVALID_CAPACITY";

    static const char *DEFAULT_DUMP_FILE_NAME = "stack.log";

    static stack_error_t stack_dump         (stack_t *     stack,
                                             const char *  filename,
                                             size_t        line,
                                             const char *  function,
                                             stack_error_t error);
    static const char *get_error_text       (stack_error_t error);
    static stack_error_t stack_init_dump    (stack_t *   stack,
                                             int       (*print)(FILE *, void *),
                                             size_t      line,
                                             const char *dump_file_name,
                                             const char *initialized_file,
                                             const char *variable_name,
                                             const char *function_name);
    static stack_error_t stack_write_members(stack_t *stack);
#endif//WRITE DUMP MODE

//=============================================================================================================
//VERIFYING AND ERROR RETURN MACROS (every mode)
//=============================================================================================================
#define STACK_VERIFY(__stack_pointer) {                               \
    stack_error_t __stack_error_state = stack_verify(__stack_pointer);\
    if(__stack_error_state != STACK_SUCCESS) {                        \
        STACK_WRITE_DUMP_ON(stack_dump(__stack_pointer,               \
                                       __FILE__,                      \
                                       __LINE__,                      \
                                       __FUNCTION__,                  \
                                       __stack_error_state));         \
        stack_destroy(__stack_pointer);                               \
        return __stack_error_state;                                   \
    }                                                                 \
}

#define STACK_RETURN_ERROR(__stack_pointer, __error_code) {\
    stack_destroy(__stack_pointer);                        \
    return __error_code;                                   \
}

#define STACK_CAPACITY(__stack_pointer, __operation) {                   \
    stack_error_t __check_size_state = stack_check_size(__stack_pointer, \
                                                        __operation    );\
    if(__check_size_state != STACK_SUCCESS)                              \
        STACK_RETURN_ERROR(__stack_pointer, __check_size_state);         \
}

enum stack_operation_t {
    OPERATION_PUSH,
    OPERATION_POP ,
};

//=============================================================================================================
//FUNCTION PROTOTYPES
//=============================================================================================================
static stack_error_t stack_check_size      (stack_t *         stack,
                                            stack_operation_t operation);
static stack_error_t stack_verify          (stack_t *stack);
static stack_error_t stack_free_data       (stack_t *stack);
static stack_error_t allocate_data         (stack_t *stack);
static stack_error_t reallocate_data       (stack_t *stack,
                                            size_t   new_capacity);

//=============================================================================================================
//FUNCTION DEFINITIONS
//=============================================================================================================
stack_error_t stack_init(STACK_WRITE_DUMP_ON(const char *initialized_file,
                                             size_t      line,
                                             const char *variable_name,
                                             const char *function_name,
                                             int       (*print)(FILE *,void *),
                                             const char *dump_file_name,)
                         stack_t *   stack,
                         size_t      init_capacity,
                         size_t      element_size) {
    if(stack == NULL)
        return STACK_NULL;

    if(stack->data != NULL)
        STACK_RETURN_ERROR(stack, STACK_DOUBLE_INIT);

    stack->init_capacity = init_capacity;
    stack->capacity      = init_capacity;
    stack->element_size  = element_size ;
    stack->size          = 0            ;

    stack_error_t allocation_state = allocate_data(stack);
    if(allocation_state != STACK_SUCCESS)
        STACK_RETURN_ERROR(stack, allocation_state);

    #ifdef WRITE_DUMP
        stack_error_t dump_init_state = stack_init_dump(stack,
                                                        print,
                                                        line,
                                                        dump_file_name,
                                                        initialized_file,
                                                        variable_name,
                                                        function_name);
        if(dump_init_state != STACK_SUCCESS)
            STACK_RETURN_ERROR(stack, dump_init_state);
    #endif//WRITE_DUMP

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH  (stack);
    STACK_VERIFY       (stack);
    return STACK_SUCCESS;
}

stack_error_t stack_push(stack_t *stack,
                         void *   elem) {
    STACK_VERIFY(stack);

    STACK_CAPACITY(stack, OPERATION_PUSH);

    void *element = (char *)stack->data + stack->size * stack->element_size;
    if(memcpy(element,
              elem,
              stack->element_size) != element)
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    stack->size++;

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH  (stack);
    STACK_VERIFY       (stack);
    return STACK_SUCCESS;
}

stack_error_t stack_pop(stack_t *stack,
                        void *   output) {
    STACK_VERIFY(stack);

    STACK_CAPACITY(stack, OPERATION_POP);

    if(stack->size == 0)
        return STACK_EMPTY;

    stack->size--;
    void *element = (char *)stack->data + stack->size * stack->element_size;
    if(memcpy(output,
              element,
              stack->element_size) != output)
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    if(memset(element,
              0,
              stack->element_size) != element)
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH  (stack);
    STACK_VERIFY       (stack);
    return STACK_SUCCESS;
}

stack_error_t stack_destroy(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    stack_error_t free_state = stack_free_data(stack);
    _memory_destroy_log();
    memset(stack, 0, sizeof(*stack));
    return free_state;
}

stack_error_t stack_check_size(stack_t *         stack,
                               stack_operation_t operation) {
    STACK_VERIFY(stack);

    size_t new_capacity = 0;
    switch(operation) {
        case OPERATION_PUSH: {
            if(stack->size < stack->capacity)
                return STACK_SUCCESS;
            new_capacity = stack->capacity * 2;
            break;
        }
        case OPERATION_POP:  {
            if(stack->size * 2 >= stack->capacity ||
               stack->capacity == stack->init_capacity)
                return STACK_SUCCESS;
            new_capacity = stack->capacity / 2;
            break;
        }
        default:             {
            return STACK_UNEXPECTED_ERROR;
        }
    }

    stack_error_t realloc_state = reallocate_data(stack, new_capacity);
    if(realloc_state != STACK_SUCCESS)
        return realloc_state;

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH  (stack);
    STACK_VERIFY       (stack);
    return STACK_SUCCESS;
}

stack_error_t stack_verify(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    #ifdef CANARY_PROTECTION
        if(canary_verify(stack) != STACK_SUCCESS)
            return STACK_MEMORY_ATTACK;
    #endif//CANARY_PROTECTION

    #ifdef HASH_PROTECTION
        if(hash_verify(stack) != STACK_SUCCESS)
            return STACK_MEMORY_ATTACK;
    #endif//HASH_PROTECTION

    if((stack->data     == NULL) !=
       (stack->capacity == 0)      )
        return STACK_NULL_DATA;

    if(stack->size > stack->capacity)
        return STACK_INCORRECT_SIZE;

    return STACK_SUCCESS;
}

stack_error_t allocate_data(stack_t *stack) {
    #ifdef CANARY_PROTECTION
        stack_error_t allocation_state = data_allocate_canary(stack);
        if(allocation_state != STACK_SUCCESS)
            STACK_RETURN_ERROR(stack, allocation_state);
    #else//CANARY_PROTECTION
        stack_error_t allocation_state = data_allocate_no_canary(stack);
        if(allocation_state != STACK_SUCCESS)
            STACK_RETURN_ERROR(stack, allocation_state);
    #endif//CANARY_PROTECTION

    return STACK_SUCCESS;
}

stack_error_t reallocate_data(stack_t *stack, size_t new_capacity) {
    #ifdef CANARY_PROTECTION
        stack->capacity = new_capacity;
        stack_error_t realloc_state = data_reallocate_canary(stack);
        if(realloc_state != STACK_SUCCESS)
            return realloc_state;
    #else//CANARY_PROTECTION
        stack_error_t realloc_state = data_reallocate_no_canary(stack, new_capacity);
        if(realloc_state != STACK_SUCCESS)
            return realloc_state;

        stack->capacity = new_capacity;
    #endif//CANARY_PROTECTION

    return STACK_SUCCESS;
}

//=============================================================================================================
//WRITE DUMP MODE FUNCTIONS DEFINITIONS
//=============================================================================================================
#ifdef WRITE_DUMP
    stack_error_t stack_dump(stack_t *     stack,
                             const char *  filename,
                             size_t        line,
                             const char *  function,
                             stack_error_t error) {
        if(stack->dump_file == NULL) {
            printf("DUMP FILE ERROR\r\n"
                   "called from: %s:%llu\r\n",
                   filename,
                   line);
            return STACK_DUMP_ERROR;
        }

        if(fprintf(stack->dump_file,
                   "stack_t[0x%p] initialized in %s:%llu as 'stack_t %s'\r\n"
                   "dump called from %s:%llu (%s)\r\n"
                   "ERROR_CODE = 0x%x",
                   stack,
                   stack->initialized_file,
                   stack->line,
                   stack->variable_name,
                   filename,
                   line,
                   function,
                   error) < 0)
            return STACK_DUMP_ERROR;

        const char *error_definition = get_error_text(error);
        if(error_definition == NULL) {
            if(fprintf(stack->dump_file,
                       "(unknown error)\r\n") < 0)
                return STACK_DUMP_ERROR;
        }
        else{
            if(fprintf(stack->dump_file,
                       "(%s)\r\n",
                       error_definition) < 0)
                return STACK_DUMP_ERROR;
        }

        if(stack == NULL)
            return STACK_NULL;

        #ifdef CANARY_PROTECTION
            if(fprintf(stack->dump_file,
                       "{\r\n"
                       "\t\t---CANARIES---\r\n"
                       "\tcanary_left       = 0x%llx;\r\n"
                       "\tdata_canary_left  = 0x%llx;\r\n"
                       "\tdata_canary_right = 0x%llx;\r\n"
                       "\tcanary_right      = 0x%llx;\r\n",
                       stack->canary_left,
                       *stack->data_canary_left,
                       *stack->data_canary_right,
                       stack->canary_right) < 0)
                return STACK_DUMP_ERROR;
        #endif

        #ifdef HASH_PROTECTION
            if(fprintf(stack->dump_file,
                       "\t\t---HASHES---\r\n"
                       "\tstructure_hash    = 0x%llx;\r\n"
                       "\tdata_hash         = 0x%llx;\r\n",
                       stack->structure_hash,
                       stack->data_hash) < 0)
                return STACK_DUMP_ERROR;
        #endif

        if(fprintf(stack->dump_file,
                   "\t\t---DEFAULT_INFO---\r\n"
                   "\tsize              =   %llu;\r\n"
                   "\tcapacity          =   %llu;\r\n"
                   "\telement_size      =   %llu;\r\n"
                   "\t\t---MEMBERS---\r\n"
                   "\tdata[0x%p]:\r\n",
                   stack->size,
                   stack->capacity,
                   stack->element_size,
                   stack->data) < 0)
            return STACK_DUMP_ERROR;

        stack_error_t members_writing_state = stack_write_members(stack);
        if(members_writing_state != STACK_SUCCESS)
            return members_writing_state;

        if(fprintf(stack->dump_file,
                   "}\r\n\r\n") < 0)
            return STACK_DUMP_ERROR;
        return STACK_SUCCESS;
    }

    stack_error_t stack_write_members(stack_t *stack) {
        if(stack->data == NULL          ) {
            if(fprintf(stack->dump_file,
                       "\t\t--- (POISON)\r\n") < 0)
                return STACK_DUMP_ERROR;

            return STACK_SUCCESS;
        }
        if(stack->size > stack->capacity) {
            if(fprintf(stack->dump_file,
                       "\t\tincorrect size\r\n") < 0)
                return STACK_DUMP_ERROR;

            return STACK_SUCCESS;
        }

        for(size_t element = 0; element < stack->size; element++) {
            if(fprintf(stack->dump_file,
                       "\t   *[%llu] = ",
                       element) < 0)
                return STACK_DUMP_ERROR;

            if(stack->print(stack->dump_file,
                            (char *)stack->data + element * stack->element_size) < 0)
                return STACK_DUMP_ERROR;

            if(fprintf(stack->dump_file,
                       ";\r\n") < 0)
                return STACK_DUMP_ERROR;
        }

        for(size_t element = stack->size; element < stack->capacity; element++) {
            if(fprintf(stack->dump_file,
                       "\t\t[%llu] = --- (POISON)\r\n",
                       element) < 0)
                return STACK_DUMP_ERROR;
        }
        return STACK_SUCCESS;
    }

    const char *get_error_text(stack_error_t error) {
        switch(error) {
            case STACK_SUCCESS:          {
                return TEXT_STACK_SUCCESS;
            }
            case STACK_UNEXPECTED_ERROR: {
                return TEXT_STACK_UNEXPECTED_ERROR;
            }
            case STACK_MEMORY_ERROR:     {
                return TEXT_STACK_MEMORY_ERROR;
            }
            case STACK_DUMP_ERROR:       {
                return TEXT_STACK_DUMP_ERROR;
            }
            case STACK_NULL:             {
                return TEXT_STACK_NULL;
            }
            case STACK_NULL_DATA:        {
                return TEXT_STACK_NULL_DATA;
            }
            case STACK_DOUBLE_INIT:      {
                return TEXT_STACK_DOUBLE_INIT;
            }
            case STACK_EMPTY:            {
                return TEXT_STACK_EMPTY;
            }
            case STACK_INCORRECT_SIZE:   {
                return TEXT_STACK_INCORRECT_SIZE;
            }
            case STACK_MEMORY_ATTACK:    {
                return TEXT_STACK_MEMORY_ATTACK;
            }
            case STACK_INVALID_CAPACITY: {
                return TEXT_STACK_INVALID_CAPACITY;
            }
            default:                     {
                return NULL;
            }
        }
    }

    stack_error_t stack_init_dump(stack_t *   stack,
                                  int       (*print)(FILE *, void *),
                                  size_t      line,
                                  const char *dump_file_name,
                                  const char *initialized_file,
                                  const char *variable_name,
                                  const char *function_name) {
        if(dump_file_name == NULL)
            dump_file_name = DEFAULT_DUMP_FILE_NAME;

        stack->dump_file = fopen(dump_file_name, "wb");

        if(stack->dump_file == NULL)
            return STACK_DUMP_ERROR;

        if(print == NULL)
            return STACK_DUMP_ERROR;

        stack->print            = print           ;
        stack->initialized_file = initialized_file;
        stack->variable_name    = variable_name   ;
        stack->line             = line            ;
        stack->initialized_func = function_name   ;
        return STACK_SUCCESS;
    }
#endif//WRITE DUMP MODE FUNCTIONS DEFINITIONS

//=============================================================================================================
//HASH PROTECTION MODE FUNCTIONS DEFINITIONS
//=============================================================================================================
#ifdef HASH_PROTECTION
    stack_error_t stack_update_hash(stack_t *stack) {
        stack_error_t hash_state = stack_count_hash(stack,
                                                    &stack->data_hash,
                                                    &stack->structure_hash);
        if(hash_state != STACK_SUCCESS)
            return hash_state;

        return STACK_SUCCESS;
    }

    size_t hash_function(void *start, void *end) {
        size_t hash = 5381;
        for(char *byte = (char *)start; byte < end; byte++)
            hash = (hash << 5) + hash + *byte;

        return hash;
    }

    stack_error_t stack_count_hash(stack_t *stack,
                                   size_t * data_hash,
                                   size_t * structure_hash) {
        if(stack == NULL)
            return STACK_NULL;

        *data_hash = hash_function(stack->data,
                                   (char *)stack->data +
                                   stack->capacity *
                                   stack->element_size);

        if(stack->data == NULL)
            return STACK_NULL_DATA;

        *structure_hash = hash_function(&stack->data,
                                        &stack->init_capacity + 1);
        return STACK_SUCCESS;
    }

    stack_error_t hash_verify(stack_t *stack) {
        size_t data_hash      = 0,
               structure_hash = 0;

        stack_error_t hash_state = stack_count_hash(stack,
                                                    &data_hash,
                                                    &structure_hash);
        if(hash_state != STACK_SUCCESS)
            return hash_state;

        if(data_hash      != stack->data_hash ||
           structure_hash != stack->structure_hash)
            return STACK_MEMORY_ATTACK;

        return STACK_SUCCESS;
    }
#endif//HASH PROTECTION MODE FUNCTIONS DEFINITIONS

//=============================================================================================================
//CANARY PROTECTION MODE FUNCTIONS DEFINITIONS
//=============================================================================================================
#ifdef CANARY_PROTECTION
    stack_error_t stack_update_canary(stack_t *stack) {
        if(stack == NULL)
            return STACK_NULL;

        stack->canary_left  = (uint64_t)stack ^ LEFT_HEX_SPEECH ;
        stack->canary_right = (uint64_t)stack ^ RIGHT_HEX_SPEECH;

        if(stack->data == NULL)
            return STACK_NULL_DATA;

        stack->data_canary_left  = (uint64_t *)((char *)stack->data -
                                              sizeof(stack->canary_left));

        stack->data_canary_right = (uint64_t *)((char *)stack->data +
                                              stack->actual_data_size -
                                              2 * sizeof(stack->canary_left));

        *stack->data_canary_left  = (uint64_t)stack->data ^ LEFT_HEX_SPEECH ;
        *stack->data_canary_right = (uint64_t)stack->data ^ RIGHT_HEX_SPEECH;
        return STACK_SUCCESS;
    }

    stack_error_t align_size(stack_t *stack) {
        size_t data_size = stack->capacity * stack->element_size;
        size_t canary_size = sizeof(stack->canary_left);
        stack->actual_data_size = data_size +
                                  2 * canary_size +
                                  (canary_size - data_size % canary_size) %
                                  canary_size;
        return STACK_SUCCESS;
    }

    stack_error_t canary_verify(stack_t *stack) {
        if(stack->canary_left  != ((uint64_t)stack ^ LEFT_HEX_SPEECH ) ||
           stack->canary_right != ((uint64_t)stack ^ RIGHT_HEX_SPEECH)   )
            return STACK_MEMORY_ATTACK;

        if(*stack->data_canary_left  != ((uint64_t)stack->data ^ LEFT_HEX_SPEECH ) ||
           *stack->data_canary_right != ((uint64_t)stack->data ^ RIGHT_HEX_SPEECH)   )
            return STACK_MEMORY_ATTACK;

        return STACK_SUCCESS;
    }

    stack_error_t data_allocate_canary(stack_t *stack) {
        stack_error_t align_state = align_size(stack);
        if(align_state != STACK_SUCCESS)
            return STACK_MEMORY_ERROR;

        stack->data = _calloc(stack->actual_data_size, 1);
        if(stack->data == NULL)
            return STACK_MEMORY_ERROR;

        stack->data = (char *)stack->data + sizeof(stack->canary_left);
        return STACK_SUCCESS;
    }

    stack_error_t data_reallocate_canary(stack_t *stack) {
        size_t old_actual_size = stack->actual_data_size;
        stack_error_t align_state = align_size(stack);
        if(old_actual_size == stack->actual_data_size)
            return STACK_SUCCESS;

        if(align_state != STACK_SUCCESS)
            return align_state;

        void *new_memory_cell = _recalloc(stack->data_canary_left,
                                          old_actual_size,
                                          stack->actual_data_size, 1);
        if(new_memory_cell == NULL)
            return STACK_MEMORY_ERROR;

        stack->data = (char *)new_memory_cell + sizeof(stack->canary_left);
        return STACK_SUCCESS;
    }

    stack_error_t stack_free_data(stack_t *stack) {
        if(stack->data != NULL)
            _free((char *)stack->data - sizeof(stack->canary_left));
        return STACK_SUCCESS;
    }
#else
    stack_error_t data_allocate_no_canary(stack_t *stack) {
        stack->data = _calloc(stack->init_capacity,
                              stack->element_size );

        if(stack->data == NULL)
            return STACK_MEMORY_ERROR;

        return STACK_SUCCESS;
    }

    stack_error_t data_reallocate_no_canary(stack_t *stack,
                                            size_t   new_capacity) {
        void *new_memory_cell = _recalloc(stack->data,
                                          stack->capacity,
                                          new_capacity,
                                          stack->element_size);

        if(new_memory_cell == NULL && new_capacity != 0)
            return STACK_MEMORY_ERROR;

        stack->data = new_memory_cell;
        return STACK_SUCCESS;
    }

    stack_error_t stack_free_data(stack_t *stack) {
        _free(stack->data);
        return STACK_SUCCESS;
    }
#endif//CANARY PROTECTION MODE FUNCTIONS DEFINITIONS
//sanjai zapilil za dve chashko riza
