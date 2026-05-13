#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Define a dummy function to act as an extension entry point
int dummy_extension_entry_point(void) {
    return SQLITE_OK;
}

int LLVMFuzzerTestOneInput_510(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test with the dummy extension entry point
    sqlite3_auto_extension((void(*)(void))dummy_extension_entry_point);

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

    LLVMFuzzerTestOneInput_510(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
