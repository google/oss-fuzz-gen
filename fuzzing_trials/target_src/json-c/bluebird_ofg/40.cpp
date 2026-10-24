#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/linkhash.h"  // Include the correct header file where lh_kptr_table_new is declared
#include <cstdlib>  // For std::abort

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an integer from the fuzzed data
    int arg1 = fuzzed_data.ConsumeIntegralInRange<int>(1, 1000);  // Ensure a reasonable range for table size

    // Define a dummy function to use as a function pointer
    // Correct the lambda to match the expected signature 'void(struct lh_entry *)'
    lh_entry_free_fn *dummy_fn = [](struct lh_entry *entry) {};

    // Call the function-under-test with the fuzzed arguments
    struct lh_table *result = lh_kptr_table_new(arg1, dummy_fn);

    // Check if the result is nullptr, which might indicate an error in allocation
    if (!result) {
        std::abort();  // Terminate the program if table creation failed
    }

    // If necessary, perform cleanup on the result
    // For example, if lh_kptr_table_new allocates memory, you might need to free it here
    lh_table_free(result);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
