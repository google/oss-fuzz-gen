#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Initialize the sqlite3_str object
    sqlite3_str *pStr = sqlite3_str_new(NULL);

    // Ensure the data is not empty
    if (size > 0) {
        // Create a null-terminated string from the input data
        char *inputStr = (char *)malloc(size + 1);
        if (inputStr == NULL) {
            sqlite3_str_finish(pStr);
            return 0;
        }
        memcpy(inputStr, data, size);
        inputStr[size] = '\0';

        // Call the function-under-test
        sqlite3_str_append(pStr, inputStr, (int)size);

        // Clean up
        free(inputStr);
    }

    // Finalize the sqlite3_str object
    sqlite3_str_finish(pStr);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_57(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
