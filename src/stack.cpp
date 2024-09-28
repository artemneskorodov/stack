#include <stdlib.h>
#include <string.h>
#include "stack.h"
#include "memory.h"


//=============================================================================================================
//DEBUG MODE
//=============================================================================================================
#ifndef NDEBUG
static const size_t LEFT_HEX_SPEECH  = 0xBAAADDED;
static const size_t RIGHT_HEX_SPEECH = 0xC000FFEE;

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

const char *DEFAULT_DUMP_FILE_NAME = "stack.log";

#define STACK_UPDATE_CANARY(__stack_pointer) {                          \
    stack_error_t __canary_state = stack_update_canary(__stack_pointer);\
    if(__canary_state != STACK_SUCCESS)                                 \
        STACK_RETURN_ERROR(__stack_pointer, __canary_state);            \
}

#define STACK_UPDATE_HASH(__stack_pointer) {                        \
    stack_error_t __hash_state = stack_update_hash(__stack_pointer);\
    if(__hash_state != STACK_SUCCESS)                               \
        STACK_RETURN_ERROR(__stack_pointer, __hash_state);          \
}

static stack_error_t stack_dump(stack_t *     stack   ,
                                const char *  filename,
                                size_t        line    ,
                                const char *  function,
                                stack_error_t error   );

static const char *get_error_text(stack_error_t error);

static stack_error_t stack_update_hash(stack_t *stack);

static size_t hash_function(void *memory, size_t size);

static stack_error_t stack_update_canary(stack_t *stack);

static stack_error_t stack_count_hash(stack_t *stack         ,
                                      size_t * data_hash     ,
                                      size_t * structure_hash);

static size_t align_capacity(size_t initial_capacity,
                             size_t element_size    );
//=============================================================================================================
//DEBUG MODE END
//=============================================================================================================

//=============================================================================================================
//NO DEBUG MODE
//=============================================================================================================
#else
#define STACK_UPDATE_CANARY(__stack_pointer)
#define STACK_UPDATE_HASH(__stack_pointer)
#endif
//=============================================================================================================
//NO DEBUG MODE END
//=============================================================================================================

//=============================================================================================================
//VERIFIER AND RETURNER
//=============================================================================================================
#define STACK_VERIFY(__stack_pointer) {                               \
    stack_error_t __stack_error_state = stack_verify(__stack_pointer);\
    if(__stack_error_state != STACK_SUCCESS) {                        \
        ON_DEBUG(stack_dump(__stack_pointer,                          \
                            __FILE__,                                 \
                            __LINE__,                                 \
                            __FUNCTION__,                             \
                            __stack_error_state));                    \
        stack_destroy(__stack_pointer);                               \
        return __stack_error_state;                                   \
    }                                                                 \
}

#define STACK_RETURN_ERROR(__stack_pointer, __error_code) {\
    stack_destroy(__stack_pointer);                        \
    return __error_code;                                   \
}
//=============================================================================================================
//VERIFIER AND RETURNER END
//=============================================================================================================

enum stack_operation_t {
    OPERATION_PUSH,
    OPERATION_POP ,
};

//=============================================================================================================
//FUNCTION PROTOTYPES
//=============================================================================================================
static stack_error_t stack_check_size(stack_t *         stack,
                                      stack_operation_t operation);

static stack_error_t stack_verify(stack_t *stack);
//=============================================================================================================
//FUNCTION PROTOTYPES END
//=============================================================================================================

//=============================================================================================================
//FUNCTION DEFINITIONS
//=============================================================================================================
stack_error_t stack_init(stack_t *   stack,
                         size_t      init_capacity,
                         size_t      element_size
               ON_DEBUG(,const char *initialized_file     )
               ON_DEBUG(,size_t      line                 )
               ON_DEBUG(,const char *variable_name        )
               ON_DEBUG(,const char *function_name        )
               ON_DEBUG(,int       (*print)(FILE *,void *))
               ON_DEBUG(,const char *dump_file_name       )) {
    if(stack == NULL)
        return STACK_NULL;

    if(stack->data != NULL)
        STACK_RETURN_ERROR(stack, STACK_DOUBLE_INIT);

    #ifndef NDEBUG
    init_capacity = align_capacity(init_capacity, element_size);
    stack->data = _calloc(init_capacity * element_size + 2 * sizeof(size_t), 1);
    #else
    stack->data = _calloc(init_capacity,
                          element_size);
    #endif

    if(stack->data == NULL)
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    #ifndef NDEBUG
    stack->data = (char *)stack->data + sizeof(stack->canary_left);

    if(dump_file_name == NULL)
        dump_file_name = DEFAULT_DUMP_FILE_NAME;

    stack->dump_file = fopen(dump_file_name, "wb");

    if(stack->dump_file == NULL)
        STACK_RETURN_ERROR(stack, STACK_DUMP_ERROR);

    if(print == NULL)
        STACK_RETURN_ERROR(stack, STACK_DUMP_ERROR);

    stack->print            = print           ;
    stack->initialized_file = initialized_file;
    stack->variable_name    = variable_name   ;
    stack->line             = line            ;
    stack->initialized_func = function_name   ;
    #endif

    stack->init_capacity = init_capacity;
    stack->capacity      = init_capacity;
    stack->element_size  = element_size ;
    stack->size          = 0            ;

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH(stack);
    STACK_VERIFY(stack);
    return STACK_SUCCESS;
}

stack_error_t stack_push(stack_t *stack,
                         void *   elem) {
    STACK_VERIFY(stack);

    stack_error_t check_size_state = stack_check_size(stack, OPERATION_PUSH);
    if(check_size_state != STACK_SUCCESS)
        STACK_RETURN_ERROR(stack, check_size_state);

    void *element_pointer = (char *)stack->data + stack->size * stack->element_size;
    if(memcpy(element_pointer    ,
              elem               ,
              stack->element_size) !=
       element_pointer               )
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    stack->size++;

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH(stack);
    STACK_VERIFY(stack);
    return STACK_SUCCESS;
}

stack_error_t stack_pop(stack_t *stack,
                        void *   output) {
    STACK_VERIFY(stack);

    stack_error_t check_size_state = stack_check_size(stack, OPERATION_POP);
    if(check_size_state != STACK_SUCCESS)
        STACK_RETURN_ERROR(stack, check_size_state);

    if(stack->size == 0)
        return STACK_EMPTY;

    stack->size--;
    void *element_pointer = (char *)stack->data + stack->size * stack->element_size;
    if(memcpy(output             ,
              element_pointer    ,
              stack->element_size) !=
       output                        )
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    if(memset(element_pointer    ,
              0                  ,
              stack->element_size) !=
       element_pointer               )
        STACK_RETURN_ERROR(stack, STACK_MEMORY_ERROR);

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH(stack);
    STACK_VERIFY(stack);
    return STACK_SUCCESS;
}

stack_error_t stack_destroy(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    #ifndef NDEBUG
    if(stack->data != NULL)
        _free((char *)stack->data - sizeof(stack->canary_left));
    #else
    _free(stack->data);
    #endif

    _memory_destroy_log();
    memset(stack, 0, sizeof(stack_t));
    return STACK_SUCCESS;
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
            if(stack->size * 2 >= stack->capacity || stack->capacity == stack->init_capacity)
                return STACK_SUCCESS;
            new_capacity = stack->capacity / 2;
            break;
        }
        default:             {
            return STACK_UNEXPECTED_ERROR;
        }
    }

    #ifndef NDEBUG
    void *new_memory_cell = _recalloc((size_t *)stack->data - 1                                 ,
                                      stack->capacity * stack->element_size + 2 * sizeof(size_t),
                                      new_capacity    * stack->element_size + 2 * sizeof(size_t),
                                      1                                                         );
    if(new_memory_cell == NULL)
        return STACK_MEMORY_ERROR;

    new_memory_cell = (char *)new_memory_cell + sizeof(stack->canary_left);
    #else
    void *new_memory_cell = _recalloc(stack->data        ,
                                      stack->capacity    ,
                                      new_capacity       ,
                                      stack->element_size);

    if(new_memory_cell == NULL && new_capacity != 0)
        return STACK_MEMORY_ERROR;
    #endif

    stack->data     = new_memory_cell;
    stack->capacity = new_capacity   ;

    STACK_UPDATE_CANARY(stack);
    STACK_UPDATE_HASH(stack);
    STACK_VERIFY(stack);
    return STACK_SUCCESS;
}

stack_error_t stack_verify(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

#ifndef NDEBUG
    if(stack->canary_left  != ((size_t)stack ^ LEFT_HEX_SPEECH ) ||
       stack->canary_right != ((size_t)stack ^ RIGHT_HEX_SPEECH))
        return STACK_MEMORY_ATTACK;

    if(*stack->data_canary_left  != ((size_t)stack->data ^ LEFT_HEX_SPEECH ) ||
       *stack->data_canary_right != ((size_t)stack->data ^ RIGHT_HEX_SPEECH))
        return STACK_MEMORY_ATTACK;

    size_t data_hash      = 0,
           structure_hash = 0;
    stack_error_t hash_state = stack_count_hash(stack, &data_hash, &structure_hash);
    if(hash_state != STACK_SUCCESS)
        return hash_state;

    if(data_hash      != stack->data_hash      ||
       structure_hash != stack->structure_hash)
        return STACK_MEMORY_ATTACK;
#endif

    if((stack->data == NULL) != (stack->capacity == 0))
        return STACK_NULL_DATA;

    if(stack->size > stack->capacity)
        return STACK_INCORRECT_SIZE;

    return STACK_SUCCESS;
}

//=============================================================================================================
//DEBUG MODE
//=============================================================================================================
#ifndef NDEBUG
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
               "stack_t[0x%p] initialized in %s:%llu\r\n"
               "dump called from %s:%llu (%s)\r\n"
               "ERROR_CODE = 0x%x",
               stack,
               stack->initialized_file,
               stack->line,
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

    if(fprintf(stack->dump_file,
               "{\r\n"
               "\tcanary_left    = 0x%llx\r\n"
               "\tstructure_hash = 0x%llx\r\n"
               "\tdata_hash      = 0x%llx\r\n"
               "\tcapacity       = %llu\r\n"
               "\tsize           = %llu\r\n"
               "\tdata[0x%p]:\r\n",
               stack->canary_left,
               stack->structure_hash,
               stack->data_hash,
               stack->capacity,
               stack->size,
               stack->data) < 0)
        return STACK_DUMP_ERROR;

    if(stack->data == NULL) {
        if(fprintf(stack->dump_file,
                   "\t\t--- (POISON)\r\n") < 0)
            return STACK_DUMP_ERROR;
    }
    else if(stack->size > stack->capacity) {
        if(fprintf(stack->dump_file,
                   "\t\tincorrect size\r\n") < 0)
            return STACK_DUMP_ERROR;
    }
    else{
        if(fprintf(stack->dump_file,
                   "\t\tdata_canary_left = 0x%llx\r\n",
                   *((size_t *)stack->data - 1)) < 0)
            return STACK_DUMP_ERROR;
        for(size_t element = 0; element < stack->size; element++) {
            if(fprintf(stack->dump_file, "\t   *[%llu] = ", element) < 0)
                return STACK_DUMP_ERROR;

            if(stack->print(stack->dump_file,
                            (char *)stack->data + element * stack->element_size) < 0)
                return STACK_DUMP_ERROR;

            if(fprintf(stack->dump_file, ";\r\n") < 0)
                return STACK_DUMP_ERROR;
        }
        for(size_t element = stack->size; element < stack->capacity; element++) {
            if(fprintf(stack->dump_file,
               "\t\t[%llu] = --- (POISON)\r\n",
               element) < 0)
                return STACK_DUMP_ERROR;
        }
        if(fprintf(stack->dump_file,
                   "\t\tdata_canary_left = 0x%llx\r\n",
                   *(size_t *)((char *)stack->data + stack->capacity * stack->element_size)) < 0)
            return STACK_DUMP_ERROR;
    }

    if(fprintf(stack->dump_file,
               "\tcanary_right = 0x%llx\r\n"
               "}\r\n\r\n",
               stack->canary_right) < 0)
        return STACK_DUMP_ERROR;
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

static stack_error_t stack_update_hash(stack_t *stack) {
    stack_error_t hash_state = stack_count_hash(stack, &stack->data_hash, &stack->structure_hash);
    if(hash_state != STACK_SUCCESS) {
        return hash_state;
    }
    return STACK_SUCCESS;
}

static size_t hash_function(void *memory, size_t size) {
    size_t hash = 5381;
    for(size_t byte = 0; byte < size; byte++)
        hash = (hash << 5) + hash + *((char *)memory + byte);

    return hash;
}

stack_error_t stack_update_canary(stack_t *stack) {
    if(stack == NULL)
        return STACK_NULL;

    stack->canary_left  = (size_t)stack ^ LEFT_HEX_SPEECH ;
    stack->canary_right = (size_t)stack ^ RIGHT_HEX_SPEECH;

    if(stack->data == NULL)
        return STACK_NULL_DATA;

    stack->data_canary_left  = (size_t *)((char *)stack->data - sizeof(size_t));
    stack->data_canary_right = (size_t *)((char *)stack->data + stack->capacity * stack->element_size);

    *stack->data_canary_left  = (size_t)stack->data ^ LEFT_HEX_SPEECH ;
    *stack->data_canary_right = (size_t)stack->data ^ RIGHT_HEX_SPEECH;
    return STACK_SUCCESS;
}

stack_error_t stack_count_hash(stack_t *stack, size_t *data_hash, size_t *structure_hash) {
    if(stack == NULL)
        return STACK_NULL;
    *data_hash = hash_function(stack->data, stack->capacity * stack->element_size);

    if(stack->data == NULL)
        return STACK_NULL_DATA;
    *structure_hash = hash_function((char *)stack + 2 * sizeof(size_t),
                                    sizeof(stack_t) - 2 * sizeof(size_t));
    return STACK_SUCCESS;
}

size_t align_capacity(size_t initial_capacity, size_t element_size) {
    while(initial_capacity * element_size % sizeof(size_t) != 0)
        initial_capacity++;
    return initial_capacity;
}
#endif
//=============================================================================================================
//DEBUG MODE END
//=============================================================================================================
