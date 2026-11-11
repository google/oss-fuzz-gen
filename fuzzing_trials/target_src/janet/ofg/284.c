#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_284(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t) + 2 * sizeof(int32_t)) {
        return 0;
    }

    int32_t n = *(const int32_t *)data;
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // Ensure n is a positive integer to avoid potential issues
    if (n <= 0) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Call the function-under-test
    JanetTable *table = janet_table_weakk(n);

    // Check if the table is not null before proceeding
    if (table) {
        // Utilize the table to maximize fuzzing results
        // Insert multiple dummy data into the table
        for (size_t i = 0; i < size / (2 * sizeof(int32_t)); i++) {
            int32_t key_int = *(const int32_t *)data;
            data += sizeof(int32_t);
            int32_t value_int = *(const int32_t *)data;
            data += sizeof(int32_t);

            Janet key = janet_wrap_integer(key_int);
            Janet value = janet_wrap_integer(value_int);
            janet_table_put(table, key, value);

            // Retrieve the value to ensure the table is functioning
            Janet retrieved = janet_table_get(table, key);
            if (!janet_checktype(retrieved, JANET_NIL)) {
                // Optionally, perform operations on the retrieved value
                // For example, check if the retrieved value matches the inserted value
                if (janet_unwrap_integer(retrieved) != value_int) {
                    // Handle unexpected behavior
                }
            }
        }

        // Additional operations to maximize fuzzing
        // Try to remove elements and check the behavior
        for (size_t i = 0; i < size / (2 * sizeof(int32_t)); i++) {
            int32_t key_int = *(const int32_t *)data;
            data += sizeof(int32_t);
            Janet key = janet_wrap_integer(key_int);
            Janet removed = janet_table_remove(table, key);
            if (!janet_checktype(removed, JANET_NIL)) {
                // Optionally, perform operations on the removed value
            }
        }

        // Deinitialize the table
        janet_table_deinit(table);
    }

    // Deinitialize the Janet environment
    janet_deinit();

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

    LLVMFuzzerTestOneInput_284(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
