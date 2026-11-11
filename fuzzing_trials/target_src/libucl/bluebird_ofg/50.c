#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_include_trace_func_t *trace_func = NULL; // Initialize to NULL as a placeholder for the function pointer
    void *user_data = (void *)data; // Using data as a placeholder for user data

    if (parser == NULL) {
        return 0;
    }

    // Call the function-under-test
    ucl_parser_set_include_tracer(parser, trace_func, user_data);

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
