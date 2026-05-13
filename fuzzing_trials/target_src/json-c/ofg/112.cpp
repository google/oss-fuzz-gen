#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    struct array_list {
        void **array;
        size_t size;
        size_t capacity;
    };

    int array_list_insert_idx(struct array_list *, size_t, void *);
}

extern "C" int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Initialize the array_list structure
    struct array_list list;
    list.capacity = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100); // Ensure capacity is at least 1
    list.size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list.capacity); // Ensure size is within capacity

    // Allocate memory for the array
    list.array = static_cast<void **>(malloc(list.capacity * sizeof(void *)));
    if (!list.array) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the array elements
    for (size_t i = 0; i < list.size; ++i) {
        list.array[i] = malloc(1); // Allocate a byte for each element
        if (!list.array[i]) {
            for (size_t j = 0; j < i; ++j) {
                free(list.array[j]);
            }
            free(list.array);
            return 0; // Exit if memory allocation fails
        }
    }

    // Consume an index within the range of the list size
    size_t index = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list.size);

    // Allocate memory for the new element to insert
    void *new_element = malloc(1); // Allocate a byte for the new element
    if (!new_element) {
        for (size_t i = 0; i < list.size; ++i) {
            free(list.array[i]);
        }
        free(list.array);
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test
    array_list_insert_idx(&list, index, new_element);

    // Free allocated memory
    for (size_t i = 0; i < list.size; ++i) {
        free(list.array[i]);
    }
    free(list.array);

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
