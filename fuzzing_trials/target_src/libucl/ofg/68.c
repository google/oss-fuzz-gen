#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    if (parser == NULL) {
        return 0;
    }

    // Feed the parser with the input data
    ucl_parser_add_chunk(parser, data, size);

    // Call the function-under-test
    const char *cur_file = ucl_parser_get_cur_file(parser);

    // Use the result to avoid compiler optimizations
    if (cur_file != NULL) {
        // Do something trivial with cur_file to ensure it's used
        volatile char first_char = cur_file[0];
        (void)first_char;
    }

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
