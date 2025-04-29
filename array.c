#ifndef ARRAY_C
#define ARRAY_C

#include <stddef.h>
#include <stdlib.h>

struct string
{
    size_t size;
    size_t capacity;
    char *buffer;
};

struct string_arr
{
    size_t size;
    size_t capacity;
    char **buffer;
};

#define array_init(arr, cap) {\
    (arr)->capacity = (cap);\
    (arr)->size = 0;\
    (arr)->buffer = calloc((arr)->capacity, sizeof(*(arr)->buffer));\
    if((arr)->buffer == NULL) die("failed alloc");\
}

#define array_clear(traverse, arr) \
    traverse(arr, x) {\
        free(*x);\
        *x = NULL;\
    }\

#define array_destroy(arr) \
    if((arr)->buffer != NULL) { free((arr)->buffer); (arr)->buffer = NULL; }\

#define array_resize(arr) \
    if((arr)->capacity <= (arr)->size) {\
        while((arr)->capacity <= (arr)->size) (arr)->capacity *= 2;\
        (arr)->buffer = realloc((arr)->buffer, (arr)->capacity * sizeof(*(arr)->buffer));\
        if((arr)->buffer == NULL) die("failed alloc");\
    }\

#define array_push(arr, value) {\
    array_resize(arr);\
    (arr)->buffer[(arr)->size++] = (value);\
}

#define array_concat(arr, rest, rest_size) {\
    typeof((arr)->size) __old_arr_size = (arr)->size;\
    (arr)->size += rest_size;\
    array_resize(arr);\
    memcpy((arr)->buffer + __old_arr_size, rest, rest_size);\
}

#define array_foreach_offset(arr, off, x)\
    for(typeof((arr)->buffer) (x) = (arr)->buffer + (off);\
        (x) != (arr)->buffer + (arr)->size;\
        (x)++)
#define array_foreach(arr, x) array_foreach_offset(arr, 0, x)

#define array_null_foreach_offset(arr, off, x)\
    for(typeof((arr)->buffer) (x) = (arr)->buffer + (off);\
        *(x) != NULL;\
        (x)++)
#define array_null_foreach(arr, x) array_null_foreach_offset(arr, 0, x)

#endif // ARRAY_C
