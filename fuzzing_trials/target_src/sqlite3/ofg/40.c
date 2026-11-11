#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Call the function-under-test
    int version_number = sqlite3_libversion_number();

    // Use the version_number in some way to ensure the call is not optimized away
    if (version_number != 0) {
        // Do something trivial with the version number
        // This is just to demonstrate that the function was called
        (void)version_number;
    }

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

    LLVMFuzzerTestOneInput_40(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
