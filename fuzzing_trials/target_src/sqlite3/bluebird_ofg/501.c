#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_501(const uint8_t *data, size_t size) {
    // Create a new sqlite3_str object
    sqlite3_str *strAccum = sqlite3_str_new(NULL);

    // Check if the object was created successfully
    if (strAccum == NULL) {
        return 0; // If not, return early
    }

    // Append the input data to the sqlite3_str object
    sqlite3_str_append(strAccum, (const char *)data, (int)size);

    // Reset the string accumulator
    sqlite3_str_reset(strAccum);

    // Free the sqlite3_str object
    sqlite3_str_finish(strAccum);

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

    LLVMFuzzerTestOneInput_501(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
