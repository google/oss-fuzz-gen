#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

// Define the array_list structure
struct array_list {
    void **array;
    size_t size;
    size_t capacity;
};

// Function to free the memory allocated for an array_list
void array_list_free(struct array_list *list) {
    if (list->array != NULL) {
        for (size_t i = 0; i < list->size; ++i) {
            if (list->array[i] != NULL) {
                free(list->array[i]);
            }
        }
        free(list->array);
        list->array = NULL;
    }
    list->size = 0;
    list->capacity = 0;
}

extern "C" int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create an array_list object
    struct array_list list;

    // Initialize the size and capacity of the array_list
    list.size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);
    list.capacity = fuzzed_data.ConsumeIntegralInRange<size_t>(list.size, 200);

    // Allocate memory for the array within the array_list
    list.array = (void **)malloc(list.capacity * sizeof(void *));
    if (list.array == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Fill the array with non-NULL pointers
    for (size_t i = 0; i < list.size; ++i) {
        list.array[i] = malloc(1); // Allocate 1 byte for each element
        if (list.array[i] == NULL) {
            // If allocation fails, free previously allocated memory and exit
            for (size_t j = 0; j < i; ++j) {
                free(list.array[j]);
            }
            free(list.array);
            return 0;
        }
    }

    // Call the function-under-test
    array_list_free(&list);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
