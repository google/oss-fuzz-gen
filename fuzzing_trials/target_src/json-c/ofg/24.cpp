#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Assuming the definition of lh_table and any necessary headers are available
struct lh_table {
    // Dummy members to simulate the structure
    int size;
    int *buckets;
};

extern "C" int lh_table_length(struct lh_table *);

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a lh_table instance
    lh_table table;
    table.size = fuzzed_data.ConsumeIntegral<int>();
    
    // Ensure there is at least one bucket
    size_t num_buckets = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100);
    table.buckets = new int[num_buckets];
    
    // Fill the buckets with fuzzed data
    for (size_t i = 0; i < num_buckets; ++i) {
        table.buckets[i] = fuzzed_data.ConsumeIntegral<int>();
    }

    // Call the function-under-test
    int length = lh_table_length(&table);

    // Clean up
    delete[] table.buckets;

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
