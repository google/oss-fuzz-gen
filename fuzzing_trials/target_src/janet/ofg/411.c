#include <stdint.h>
#include <janet.h>
#include <stdio.h> // Include for debugging purposes

int LLVMFuzzerTestOneInput_411(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetBuffer to hold the input data
    JanetBuffer *buffer = janet_buffer(size);
    janet_buffer_push_bytes(buffer, data, size);

    // Use janet_compile to parse and compile the data
    JanetTable *env = janet_core_env(NULL);
    Janet result;
    JanetParser parse_state;
    janet_parser_init(&parse_state);

    enum JanetParserStatus status;
    while ((status = janet_parser_status(&parse_state)) != JANET_PARSE_ERROR &&
           status != JANET_PARSE_ROOT) {
        for (size_t i = 0; i < buffer->count; i++) {
            janet_parser_consume(&parse_state, buffer->data[i]);
            if (status == JANET_PARSE_PENDING) {
                result = janet_parser_produce(&parse_state);
                if (janet_checktype(result, JANET_NIL)) {
                    printf("Parsing failed or resulted in nil\n");
                } else {
                    printf("Parsing succeeded\n");
                }
            }
        }
    }

    // Clean up
    janet_parser_deinit(&parse_state);
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

    LLVMFuzzerTestOneInput_411(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
