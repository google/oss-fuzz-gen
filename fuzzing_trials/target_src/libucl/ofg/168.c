#include <stdint.h>
#include <stdio.h>
#include <ucl.h>

// Define a simple include tracer function
void include_tracer(const char *filename, void *ud) {
    // For fuzzing purposes, we can just print the filename
    // In a real application, you might want to do more complex tracing
    (void)ud; // Unused parameter
    printf("Including file: %s\n", filename);
}

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    void *user_data = (void *)data; // Use the input data as user data

    // Initialize the parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0; // Return if parser creation fails
    }

    // Call the function-under-test
    ucl_parser_set_include_tracer(parser, include_tracer, user_data);

    // Clean up
    ucl_parser_free(parser);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_168(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
