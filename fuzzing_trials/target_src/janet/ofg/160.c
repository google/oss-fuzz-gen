#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>  // Include for printf
#include <janet.h>

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetParser instance
    JanetParser parser;
    janet_parser_init(&parser);

    // Feed the data to the parser, one byte at a time
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(&parser, data[i]);
    }

    // Call the function-under-test
    const char *error_message = janet_parser_error(&parser);

    // Optionally, you can print the error message for debugging purposes
    if (error_message != NULL) {
        printf("Parser Error: %s\n", error_message);
    }

    // Clean up the parser
    janet_parser_deinit(&parser);

    // Deinitialize Janet environment
    janet_deinit();

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

    LLVMFuzzerTestOneInput_160(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
