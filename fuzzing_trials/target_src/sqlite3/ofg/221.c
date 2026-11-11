#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version = sqlite3_libversion();

    // Print the version for debugging purposes
    printf("SQLite version: %s\n", version);

    // The function does not take any input or produce any output that affects the fuzzing process
    // Therefore, we do not need to use the `data` or `size` parameters

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

    LLVMFuzzerTestOneInput_221(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
