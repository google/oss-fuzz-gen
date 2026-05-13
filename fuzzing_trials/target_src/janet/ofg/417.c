#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Fuzzing harness for janet_parser_deinit
int LLVMFuzzerTestOneInput_417(const uint8_t *data, size_t size) {
    JanetParser parser;

    // Initialize the parser with some default values
    janet_parser_init(&parser);

    // Call the function-under-test
    janet_parser_deinit(&parser);

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

    LLVMFuzzerTestOneInput_417(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
