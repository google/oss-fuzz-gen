#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Ensure that the Janet library is initialized before using any of its functions
__attribute__((constructor))
static void initialize_janet_569() {
    janet_init();
}

// Fuzzing harness for the janet_table_weakk function
int LLVMFuzzerTestOneInput_569(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to extract an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t count = *(const int32_t *)data;

    // Ensure count is a reasonable value for fuzzing
    if (count < 0 || count > 1000) {
        return 0;
    }

    // Call the function-under-test
    JanetTable *table = janet_table_weakk(count);

    // Utilize the table to increase effectiveness of fuzzing
    if (table) {
        // Insert some dummy data into the table
        Janet key = janet_wrap_integer(1);
        Janet value = janet_wrap_integer(2);
        janet_table_put(table, key, value);

        // Retrieve the value to ensure the table is functioning
        Janet retrieved_value = janet_table_get(table, key);
        if (janet_unwrap_integer(retrieved_value) != 2) {
            // There might be an issue if the retrieved value is not as expected
            return 0;
        }
    }

    // Perform any necessary cleanup
    // JanetTable is a Janet object, and Janet handles memory management internally

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_569(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
