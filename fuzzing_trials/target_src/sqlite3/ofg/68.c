#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a sqlite3_str object
    sqlite3_str *str = sqlite3_str_new(NULL);

    // Ensure that the data is null-terminated for safe string operations
    char *nullTerminatedData = (char *)malloc(size + 1);
    if (nullTerminatedData == NULL) {
        return 0;
    }
    memcpy(nullTerminatedData, data, size);
    nullTerminatedData[size] = '\0';

    // Append the data to the sqlite3_str object
    sqlite3_str_appendall(str, nullTerminatedData);

    // Call the function-under-test
    char *result = sqlite3_str_finish(str);

    // Free the result if it's not NULL
    if (result != NULL) {
        sqlite3_free(result);
    }

    // Free the allocated memory
    free(nullTerminatedData);

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

    LLVMFuzzerTestOneInput_68(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
