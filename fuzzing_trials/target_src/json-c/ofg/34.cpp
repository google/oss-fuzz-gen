#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

extern "C" {

struct array_list {
    void **array;
    size_t size;
};

void * array_list_get_idx(struct array_list *, size_t);

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create an array_list object
    struct array_list list;
    list.size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100); // Ensure size is non-zero

    // Allocate memory for the array
    std::vector<void*> elements(list.size);
    for (size_t i = 0; i < list.size; ++i) {
        elements[i] = reinterpret_cast<void*>(fuzzed_data.ConsumeIntegral<uintptr_t>());
    }
    list.array = elements.data();

    // Get an index to access
    size_t index = fuzzed_data.ConsumeIntegralInRange<size_t>(0, list.size - 1);

    // Call the function-under-test
    void *result = array_list_get_idx(&list, index);

    return 0;
}

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
