#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "stack.h"
#include "memory.h"
#include "colors.h"
#include "custom_assert.h"

//==============================================================================
//PROTECTION MODES ON
//==============================================================================
#define STACK_HASH_PROTECTION
#define STACK_CANARY_PROTECTION
#define STACK_WRITE_DUMP

//==============================================================================
//OPERATIONS WITH STACK
//==============================================================================
enum stack_operation_t {
    STACK_OPERATION_PUSH,
    STACK_OPERATION_POP ,
};

//==============================================================================
//MACRO TO DESTROY STACK AND RETURN ERROR
//==============================================================================
#define STACK_RETURN_ERROR(__stack_pointer, __return_value) {\
    stack_destroy(&__stack_pointer);                         \
    return __return_value;                                   \
}

//==============================================================================
//MACRO TO CHECK IF STACK SIZE IS SUFFICIENT AND EXPAND IT IF NEEDED
//==============================================================================
#define STACK_CHECK_SIZE(__stack_pointer, __operation) {          \
    stack_error_t __error_code = stack_check_size(__stack_pointer,\
                                                  __operation);   \
    if(__error_code != STACK_SUCCESS)                             \
        STACK_RETURN_ERROR(*__stack_pointer, __error_code);       \
}

//==============================================================================
//CHECK IF STACK IS VALID, WRITE DUMP AND RETURN ERROR IF NOT
//==============================================================================
#define STACK_VERIFY(__stack_pointer) {                        \
    stack_error_t __error_code = stack_verify(__stack_pointer);\
    STACK_DUMP(__stack_pointer, __error_code);             \
    if(__error_code != STACK_SUCCESS) {                        \
        STACK_DUMP(__stack_pointer, __error_code);             \
        stack_destroy(&__stack_pointer);                       \
        return __error_code;                                   \
    }                                                          \
}

//==============================================================================
//FUNCTIONS PROTOTYPES
//==============================================================================
static stack_error_t stack_check_size(stack_t **stack, stack_operation_t operation);
static stack_error_t stack_verify(stack_t *stack);

//==============================================================================
//STACK WRITE DUMP MODE
//==============================================================================
#ifdef STACK_WRITE_DUMP

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
    static const char *TEXT_STACK_INVALID_INPUT    = "STACK_INVALID_INPUT"   ;
    static const char *TEXT_STACK_INVALID_OUTPUT   = "STACK_INVALID_OUTPUT"  ;

    #define STACK_DUMP(__stack_pointer, __error)\
        stack_dump(__stack_pointer,             \
                   __FILE_NAME__,               \
                   __PRETTY_FUNCTION__,         \
                   __LINE__,                    \
                   __error);

    static stack_error_t stack_dump(stack_t *stack,
                                    const char *file_name,
                                    const char *function_name,
                                    size_t line,
                                    stack_error_t call_reason);
    static const char *get_error_text(stack_error_t error);
    static stack_error_t stack_write_members(stack_t *stack);
    static stack_error_t write_stack_members_with_flags(stack_t *stack);
#else
    #define STACK_DUMP(...)
#endif

//==============================================================================
//PROTECTION OF STACK WITH HASH MODE
//==============================================================================
#ifdef STACK_HASH_PROTECTION
    typedef uint64_t hash_t;

    #define HASH_PROTECTION_ON(...) __VA_ARGS__
    #define STACK_UPDATE_HASH(__stack_pointer) {                        \
        stack_error_t __error_code = stack_update_hash(__stack_pointer);\
        if(__error_code != STACK_SUCCESS)                               \
            STACK_RETURN_ERROR(__stack_pointer, __error_code);          \
    }

    static stack_error_t stack_update_hash(stack_t *stack);
    static stack_error_t stack_count_hashes(stack_t *stack,
                                            hash_t * structure_hash,
                                            hash_t * data_hash);
    static hash_t hash_function(const void *start,
                                const void *end);
    static stack_error_t stack_verify_hashes(stack_t *stack);
#else
    #define HASH_PROTECTION_ON(...)
    #define STACK_UPDATE_HASH(__stack_pointer)
#endif

//==============================================================================
//PROTECTION OF STACK WITH CANARIES MODE
//==============================================================================
#ifdef STACK_CANARY_PROTECTION
    typedef uint64_t canary_t;
    #define CANARY_PROTECTION_ON(...) __VA_ARGS__
    #define STACK_UPDATE_CANARY(__stack_pointer) {                        \
        stack_error_t __error_code = stack_update_canary(__stack_pointer);\
        if(__error_code != STACK_SUCCESS)                                 \
            STACK_RETURN_ERROR(__stack_pointer, __error_code);            \
    }

    static stack_error_t stack_update_canary(stack_t *stack);
    static size_t count_alignment_offset(size_t capacity, size_t element_size);
    static stack_error_t stack_verify_canaries(stack_t *stack);
#else
    #define CANARY_PROTECTION_ON(...)
    #define STACK_UPDATE_CANARY(__stack_pointer)
#endif

//==============================================================================
//THE DEFINITION OF STACK STRUCTURE
//==============================================================================
struct stack_t {
    #ifdef STACK_CANARY_PROTECTION
        canary_t  structure_left_canary;
        canary_t *data_left_canary;
        canary_t *data_right_canary;
        size_t    alignment_offset;
    #endif

    #ifdef STACK_HASH_PROTECTION
        hash_t structure_hash;
        hash_t data_hash;
    #endif

    #ifdef STACK_WRITE_DUMP
        FILE *      dump_file;
        const char *dump_filename;
        const char *initialized_file;
        const char *initialized_varname;
        const char *initialized_function;
        size_t      initialized_line;
        int       (*print_func)(FILE *, void *);
    #endif

    size_t size;
    size_t capacity;
    size_t init_capacity;
    size_t element_size;
    char * data;

    #ifdef STACK_CANARY_PROTECTION
        canary_t structure_right_canary;
    #endif
};

//==============================================================================
//GLOBAL FUNCTION
//==============================================================================

//------------------------------------------------------------------------------
//INITIALIZES STACK
//------------------------------------------------------------------------------
stack_t *stack_init(STACK_WRITE_DUMP_ON(const char *dump_filename,
                                        const char *initialized_file,
                                        const char *initialized_varname,
                                        const char *initialized_function,
                                        size_t      initialized_line,
                                        int       (*print_func)(FILE *, void *),)
                    size_t capacity,
                    size_t element_size) {
    C_ASSERT(element_size != 0, return NULL);
    #ifdef STACK_WRITE_DUMP
        C_ASSERT(dump_filename        != NULL, return NULL);
        C_ASSERT(initialized_file     != NULL, return NULL);
        C_ASSERT(initialized_varname  != NULL, return NULL);
        C_ASSERT(initialized_function != NULL, return NULL);
        C_ASSERT(print_func           != NULL, return NULL);
    #endif

    size_t allocation_size = sizeof(stack_t) + capacity * element_size;

    #ifdef STACK_CANARY_PROTECTION
        size_t alignment_offset = count_alignment_offset(capacity, element_size);
        allocation_size += alignment_offset + 2 * sizeof(canary_t);
    #endif

    stack_t *stack = (stack_t *)_calloc(allocation_size, 1);
    if(stack == NULL)
        return NULL;

    stack->capacity = capacity;
    stack->element_size = element_size;
    stack->init_capacity = capacity;
    stack->data = (char *)stack + sizeof(stack_t);

    #ifdef STACK_CANARY_PROTECTION
        stack->data              = stack->data + sizeof(canary_t);
        stack->alignment_offset  = alignment_offset;
    #endif

    #ifdef STACK_WRITE_DUMP
        stack->dump_filename        = dump_filename;
        stack->initialized_file     = initialized_file;
        stack->initialized_varname  = initialized_varname;
        stack->initialized_function = initialized_function;
        stack->initialized_line     = initialized_line;
        stack->print_func           = print_func;

        stack->dump_file = fopen(stack->dump_filename, "wb");
        if(stack->dump_file == NULL) {
            stack_destroy(&stack);
            return NULL;
        }
    #endif

    #ifdef STACK_HASH_PROTECTION
        if(stack_update_hash(stack) != STACK_SUCCESS) {
            stack_destroy(&stack);
            return NULL;
        }
    #endif

    #ifdef STACK_CANARY_PROTECTION
        if(stack_update_canary(stack) != STACK_SUCCESS) {
            stack_destroy(&stack);
            return NULL;
        }
    #endif

    if(stack_verify(stack) != STACK_SUCCESS) {
        stack_destroy(&stack);
        return NULL;
    }
    return stack;
}

//------------------------------------------------------------------------------
//PUSHES ELEMENT IN STACK
//------------------------------------------------------------------------------
stack_error_t stack_push(stack_t **stack, void *element) {
    C_ASSERT(stack   != NULL, return STACK_NULL         );
    C_ASSERT(element != NULL, return STACK_INVALID_INPUT);

    STACK_VERIFY(*stack);
    STACK_CHECK_SIZE(stack, STACK_OPERATION_PUSH);

    char *stack_storage = (*stack)->data + (*stack)->element_size * (*stack)->size;
    if(memcpy(stack_storage,
              element,
              (*stack)->element_size) != stack_storage)
        STACK_RETURN_ERROR(*stack, STACK_MEMORY_ERROR);

    (*stack)->size++;

    STACK_UPDATE_HASH  (*stack);
    STACK_UPDATE_CANARY(*stack);
    STACK_VERIFY       (*stack);
    return STACK_SUCCESS;
}

//------------------------------------------------------------------------------
//POPS ELEMENT FROM STACK, WRITES ELEMENT TO OUTPUT
//------------------------------------------------------------------------------
stack_error_t stack_pop(stack_t **stack, void *output) {
    C_ASSERT(stack  != NULL, return STACK_NULL          );
    C_ASSERT(output != NULL, return STACK_INVALID_OUTPUT);

    STACK_VERIFY(*stack);
    STACK_CHECK_SIZE(stack, STACK_OPERATION_POP);

    if((*stack)->size == 0)
        return STACK_EMPTY;

    (*stack)->size--;
    char *stack_storage = (*stack)->data + (*stack)->size * (*stack)->element_size;
    if(memcpy(output,
              stack_storage,
              (*stack)->element_size) != output)
        STACK_RETURN_ERROR(*stack, STACK_MEMORY_ERROR);

    if(memset(stack_storage,
              0,
              (*stack)->element_size) != stack_storage)
        STACK_RETURN_ERROR(*stack, STACK_MEMORY_ERROR);

    STACK_UPDATE_HASH  (*stack);
    STACK_UPDATE_CANARY(*stack);
    STACK_VERIFY       (*stack);
    return STACK_SUCCESS;
}

//------------------------------------------------------------------------------
//DESTROYS STACK
//------------------------------------------------------------------------------
stack_error_t stack_destroy(stack_t **stack) {
    C_ASSERT(stack != NULL, return STACK_NULL);

    STACK_WRITE_DUMP_ON(fclose((*stack)->dump_file));
    _free(*stack);
    _memory_destroy_log();

    *stack = NULL;
    return STACK_SUCCESS;
}

//==============================================================================
//STATIC FUNCTIONS
//==============================================================================

//------------------------------------------------------------------------------
//CHECKS IF SIZE OF STACK IS SUFFICIENT
//------------------------------------------------------------------------------
stack_error_t stack_check_size(stack_t **stack, stack_operation_t operation) {
    if(stack == NULL)
        return STACK_NULL;

    STACK_VERIFY(*stack);

    size_t new_capacity = 0;

    switch(operation) {
        case STACK_OPERATION_PUSH: {
            if((*stack)->size < (*stack)->capacity)
                return STACK_SUCCESS;
            new_capacity = (*stack)->capacity * 2;
            break;
        }
        case STACK_OPERATION_POP:  {
            if((*stack)->size * 4 > (*stack)->capacity ||
               (*stack)->init_capacity == (*stack)->capacity)
                return STACK_SUCCESS;
            new_capacity = (*stack)->capacity / 4 + (*stack)->capacity % 4;
            break;
        }
        default:                   {
            return STACK_UNEXPECTED_ERROR;
        }
    }

    #ifdef STACK_CANARY_PROTECTION
        size_t offset = count_alignment_offset(new_capacity, (*stack)->element_size);
    #endif

    size_t old_size = sizeof(stack_t) + (*stack)->capacity * (*stack)->element_size;
    size_t new_size = sizeof(stack_t) + new_capacity * (*stack)->element_size;


    #ifdef STACK_CANARY_PROTECTION
        old_size += 2 * sizeof(canary_t) + (*stack)->alignment_offset;
        new_size += 2 * sizeof(canary_t) + offset;
    #endif

    stack_t *new_stack = (stack_t *)_recalloc(*stack, old_size, new_size, 1);
    if(new_stack == NULL)
        return STACK_MEMORY_ERROR;

    #ifdef STACK_CANARY_PROTECTION
        if(operation == STACK_OPERATION_PUSH) {
            canary_t *old = (canary_t *)((char *)(new_stack + 1) +
                                         sizeof(canary_t) +
                                         new_stack->capacity *
                                         new_stack->element_size);
            *old = 0;
        }
    #endif

    *stack = new_stack;
    new_stack->capacity = new_capacity;
    new_stack->data = (char *)(new_stack + 1);

    #ifdef STACK_CANARY_PROTECTION
        new_stack->data += sizeof(canary_t);
        new_stack->alignment_offset = offset;
    #endif

    STACK_UPDATE_HASH  (*stack);
    STACK_UPDATE_CANARY(*stack);
    STACK_VERIFY       (*stack);
    return STACK_SUCCESS;
}

//------------------------------------------------------------------------------
//CHECKS IF STACK IS VALID
//------------------------------------------------------------------------------
stack_error_t stack_verify(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    if(stack->data == NULL)
        return STACK_NULL_DATA;

    #ifdef STACK_CANARY_PROTECTION
        stack_error_t canary_state = stack_verify_canaries(stack);
        if(canary_state != STACK_SUCCESS)
            return canary_state;
    #endif

    #ifdef STACK_HASH_PROTECTION
        stack_error_t hash_state = stack_verify_hashes(stack);
        if(hash_state != STACK_SUCCESS)
            return hash_state;
    #endif

    return STACK_SUCCESS;
}

//==============================================================================
//STACK WRITE DUMP MODE FUNCTIONS DEFINITION
//==============================================================================
#ifdef STACK_WRITE_DUMP
    //------------------------------------------------------------------------------
    //WRITES STACK INFORMATION IN DUMP FILE
    //------------------------------------------------------------------------------
    stack_error_t stack_dump(stack_t *stack,
                             const char *file_name,
                             const char *function_name,
                             size_t line,
                             stack_error_t call_reason) {
        if(stack->dump_file == NULL) {
            color_printf(RED_TEXT, BOLD_TEXT, DEFAULT_BACKGROUND,
                         "MEMORY DUMP FILE ERROR\r\n"
                         "called from: %s:%llu\r\n",
                         file_name,
                         line);
            return STACK_DUMP_ERROR;
        }

        if(fprintf(stack->dump_file,
                   "stack_t[0x%p] initialized in %s:%llu as 'stack_t %s' in function '%s'\r\n"
                   "dump called from %s:%llu '%s'\r\n"
                   "ERROR = ",
                   stack,
                   stack->initialized_file,
                   stack->initialized_line,
                   stack->initialized_varname,
                   stack->initialized_function,
                   file_name,
                   line,
                   function_name) < 0)
            return STACK_DUMP_ERROR;

        const char *error_definition = get_error_text(call_reason);
        if(error_definition == NULL)
            error_definition = "'unknown error'";

        if(fprintf(stack->dump_file,
                   "'%s'\r\n",
                   error_definition) < 0)
            return STACK_DUMP_ERROR;

        if(stack == NULL)
            return STACK_NULL;

        #ifdef STACK_CANARY_PROTECTION
            if(fprintf(stack->dump_file,
                       "{\r\n"
                       "\t\t---CANARIES---\r\n"
                       "\tcanary_left       = 0x%llx;\r\n"
                       "\tdata_canary_left [0x%p] = 0x%llx;\r\n"
                       "\tdata_canary_right[0x%p] = 0x%llx;\r\n"
                       "\tcanary_right      = 0x%llx;\r\n",
                       stack->structure_left_canary,
                       stack->data_left_canary,
                       *(stack->data_left_canary),
                       stack->data_right_canary,
                       *(stack->data_right_canary),
                       stack->structure_right_canary) < 0)
                return STACK_DUMP_ERROR;
        #endif

        #ifdef STACK_HASH_PROTECTION
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

        fflush(stack->dump_file);
        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //WRITES STACK MEMBERS
    //------------------------------------------------------------------------------
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

        stack_error_t flags_printing_error = write_stack_members_with_flags(stack);
        if(flags_printing_error != STACK_SUCCESS)
            return flags_printing_error;

        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //WRITES STACK MEMBERS WITH * BEFORE INDEX AND (POISON) AFTER ELEMENT IF IT IS
    //------------------------------------------------------------------------------
    stack_error_t write_stack_members_with_flags(stack_t *stack) {
        const char *POISON_ELEMENT_FLAG = " (POISON)";
        const char *NORMAL_ELEMENT_FLAG = "";
        const char *POISON_INDEX_FLAG   = "*";
        const char *NORMAL_INDEX_FLAG   = " ";

        for(size_t element = 0; element < stack->capacity; element++) {
            const char *index_flag = NULL;
            const char *element_flag = NULL;

            if(element < stack->size) {
                index_flag = NORMAL_INDEX_FLAG;
                element_flag = NORMAL_ELEMENT_FLAG;
            }
            else{
                index_flag = POISON_INDEX_FLAG;
                element_flag = POISON_ELEMENT_FLAG;
            }

            if(fprintf(stack->dump_file,
                       "\t   %s[%llu] = ",
                       index_flag,
                       element) < 0)
                return STACK_DUMP_ERROR;

            if(stack->print_func(stack->dump_file,
                            (char *)stack->data + element * stack->element_size) < 0)
                return STACK_DUMP_ERROR;

            if(fprintf(stack->dump_file,
                       "%s;\r\n",
                       element_flag) < 0)
                return STACK_DUMP_ERROR;
        }
        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //RETURNS STRING WITH TEXT DEFINITION OF ERROR
    //------------------------------------------------------------------------------
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
            case STACK_INVALID_INPUT:    {
                return TEXT_STACK_INVALID_INPUT;
            }
            case STACK_INVALID_OUTPUT:   {
                return TEXT_STACK_INVALID_OUTPUT;
            }
            default:                     {
                return NULL;
            }
        }
    }
#endif

//==============================================================================
//STACK CANARY PROTECTION MODE FUNCTIONS DEFINITION
//==============================================================================
#ifdef STACK_CANARY_PROTECTION
    //------------------------------------------------------------------------------
    //COUNTS CANARIES AND WRITES THEM INTO STACK STRUCTURE
    //------------------------------------------------------------------------------
    stack_error_t stack_update_canary(stack_t *stack) {
        stack->data_left_canary  = (canary_t *)((char *)stack + sizeof(stack_t));
        stack->data_right_canary = (canary_t *)((char *)stack + sizeof(stack_t) + sizeof(canary_t) + stack->capacity * stack->element_size + stack->alignment_offset);

        *(stack->data_left_canary ) = (canary_t)stack->data;
        *(stack->data_right_canary) = (canary_t)stack->data;

        stack->structure_left_canary  = (canary_t)stack;
        stack->structure_right_canary = (canary_t)stack;
        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //RETURNS OFFSET WHICH IS NEEDED TO ALIGN RIGHT DATA CANARY
    //------------------------------------------------------------------------------
    size_t count_alignment_offset(size_t capacity, size_t element_size) {
        return (sizeof(canary_t) - capacity * element_size % sizeof(canary_t)) % sizeof(canary_t);
    }

    //------------------------------------------------------------------------------
    //CHECKS IF CURRENT CANARIES ARE SAME AS WRITTEN IN STACK STRUCTURE
    //------------------------------------------------------------------------------
    stack_error_t stack_verify_canaries(stack_t *stack) {
        if(stack->structure_left_canary  != (canary_t)stack ||
           stack->structure_right_canary != (canary_t)stack)
            return STACK_MEMORY_ATTACK;

        if(*(stack->data_left_canary ) != (canary_t)stack->data ||
           *(stack->data_right_canary) != (canary_t)stack->data)
            return STACK_MEMORY_ATTACK;

        return STACK_SUCCESS;
    }
#endif

//==============================================================================
//STACK HASH PROTECTION MODE FUNCTIONS DEFINITION
//==============================================================================
#ifdef STACK_HASH_PROTECTION
    //------------------------------------------------------------------------------
    //FUNCTION UPDATES STACK HASHES
    //------------------------------------------------------------------------------
    stack_error_t stack_update_hash(stack_t *stack) {
        stack_error_t error_code = stack_count_hashes(stack,
                                                      &stack->structure_hash,
                                                      &stack->data_hash);
        if(error_code != STACK_SUCCESS)
            return error_code;

        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //FUNCTION WRITES HASHES IN structure hash and data hash
    //------------------------------------------------------------------------------
    stack_error_t stack_count_hashes(stack_t *stack,
                                     hash_t * structure_hash,
                                     hash_t * data_hash) {
        if(stack == NULL)
            return STACK_NULL;
        *structure_hash = hash_function(&stack->size,
                                        &stack->data + 1);
        *data_hash      = hash_function(stack->data,
                                        stack->data +
                                        stack->capacity *
                                        stack->element_size);
        return STACK_SUCCESS;
    }

    //------------------------------------------------------------------------------
    //HASH FUNCTION djb2, COUNTS HASH FROM START TO END
    //------------------------------------------------------------------------------
    hash_t hash_function(const void *start,
                         const void *end) {
        hash_t hash = 5381;
        for(const char *byte_pointer = (const char *)start; byte_pointer < end; byte_pointer++)
            hash = (hash << 5) + hash + *byte_pointer;
        return hash;
    }

    //------------------------------------------------------------------------------
    //CHECKS IF CURRENT HASH IS SAME AS WRITTEN IN STACK STRUCTURE
    //------------------------------------------------------------------------------
    stack_error_t stack_verify_hashes(stack_t *stack) {
        hash_t structure_hash = 0,
               data_hash      = 0;

        stack_error_t error_code = stack_count_hashes(stack,
                                                      &structure_hash,
                                                      &data_hash);
        if(error_code != STACK_SUCCESS)
            return error_code;

        if(stack->structure_hash != structure_hash) {
            printf("struct\n");
            return STACK_MEMORY_ATTACK;
        }

        if(stack->data_hash != data_hash) {
            printf("data\n");
            return STACK_MEMORY_ATTACK;
        }

        if(stack->structure_hash != structure_hash ||
           stack->data_hash      != data_hash)
            return STACK_MEMORY_ATTACK;

        return STACK_SUCCESS;
    }
#endif
