#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for testing
    if (size < 1) {
        return 0;
    }
    
    // Initialize a sqlite3_str object
    sqlite3_str *str = sqlite3_str_new(NULL);
    
    // Ensure that the data is null-terminated for the const char* parameter
    char *inputStr = (char *)malloc(size + 1);
    if (inputStr == NULL) {
        sqlite3_str_finish(str);
        return 0;
    }
    memcpy(inputStr, data, size);
    inputStr[size] = '\0';

    // Call the function-under-test
    sqlite3_str_appendall(str, inputStr);

    // Clean up
    free(inputStr);
    sqlite3_str_finish(str);

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

    LLVMFuzzerTestOneInput_36(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
