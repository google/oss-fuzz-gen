#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include <string.h>  // Include for NULL
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Initialize a sqlite3_str object
    sqlite3_str *str = sqlite3_str_new(NULL);

    // Check if the sqlite3_str object is created successfully
    if (str == NULL) {
        return 0;
    }

    // Append the fuzzing data to the sqlite3_str object
    sqlite3_str_append(str, (const char *)data, size);

    // Call the function-under-test
    char *result = sqlite3_str_value(str);

    // Use the result in some way to prevent it from being optimized away
    if (result != NULL) {
        volatile char dummy = result[0];
        (void)dummy;
    }

    // Free the sqlite3_str object
    sqlite3_str_finish(str);

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

    LLVMFuzzerTestOneInput_143(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
