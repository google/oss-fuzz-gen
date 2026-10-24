#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct array_list {
    void **array;
    size_t size;
    size_t capacity;
};

extern "C" int array_list_shrink(struct array_list *, size_t);

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Initialize array_list structure
    struct array_list list;
    list.capacity = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 1000); // Ensure capacity is non-zero
    list.size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list.capacity);

    // Allocate memory for the array
    list.array = static_cast<void **>(malloc(list.capacity * sizeof(void *)));
    if (!list.array) {
        return 0; // Exit if memory allocation fails
    }

    // Fill the array with non-null pointers
    for (size_t i = 0; i < list.size; ++i) {
        list.array[i] = malloc(1); // Allocate minimal memory for each element
        if (!list.array[i]) {
            for (size_t j = 0; j < i; ++j) {
                free(list.array[j]);
            }
            free(list.array);
            return 0; // Exit if memory allocation fails
        }
    }

    // Consume a size_t value for the shrink size
    size_t shrink_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list.size);

    // Call the function-under-test
    array_list_shrink(&list, shrink_size);

    // Clean up allocated memory
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
