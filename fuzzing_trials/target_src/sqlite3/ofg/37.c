#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include this for malloc and free

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Initialize a sqlite3_str object
    sqlite3_str *str = sqlite3_str_new(NULL);

    // Ensure the data is null-terminated for use as a C string
    char *cstr = (char *)malloc(size + 1);
    if (cstr == NULL) {
        return 0;
    }
    memcpy(cstr, data, size);
    cstr[size] = '\0';

    // Call the function-under-test
    sqlite3_str_appendall(str, cstr);

    // Clean up
    sqlite3_str_finish(str);
    free(cstr);

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

    LLVMFuzzerTestOneInput_37(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
