#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

extern "C" {
#include "/src/json-c/arraylist.h" // Correct path for the array_list header
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0; // Not enough data to proceed
    }

    FuzzedDataProvider fuzzed_data(data, size);

    // Create an array_list object
    struct array_list *list = array_list_new(NULL);
    if (!list) {
        return 0; // Failed to create the list
    }

    // Consume a size_t index from the fuzzed data
    size_t index = fuzzed_data.ConsumeIntegral<size_t>();

    // Consume remaining bytes as a void* data
    std::vector<uint8_t> buffer = fuzzed_data.ConsumeRemainingBytes<uint8_t>();
    void *element_data = buffer.data();

    // Call the function-under-test
    array_list_put_idx(list, index, element_data);

    // Clean up
    array_list_free(list);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
