#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Function signature provided for fuzzing
const char *sqlite3_sourceid();

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *source_id = sqlite3_sourceid();

    // Print the result to ensure the function is called and output is captured
    printf("SQLite Source ID: %s\n", source_id);

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

    LLVMFuzzerTestOneInput_38(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
