#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assuming the definition of struct array_list is available
struct array_list {
    void **array;
    size_t size;
};

// Mock implementation of array_list_get_idx
void *array_list_get_idx(struct array_list *list, size_t index) {
    if (list == nullptr || index >= list->size) {
        return nullptr;
    }
    return list->array[index];
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0;
    }

    FuzzedDataProvider fuzzed_data(data, size);

    // Create a mock array_list object
    size_t list_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100);
    struct array_list list;
    list.size = list_size;
    list.array = (void **)malloc(list_size * sizeof(void *));

    if (list.array == nullptr) {
        return 0;
    }

    // Fill the array with non-null pointers
    for (size_t i = 0; i < list_size; ++i) {
        list.array[i] = (void *)((uintptr_t)fuzzed_data.ConsumeIntegral<size_t>());
    }

    // Consume an index to access
    size_t index = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list_size - 1);

    // Call the function-under-test
    void *result = array_list_get_idx(&list, index);

    // Clean up
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
