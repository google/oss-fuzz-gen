#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    const char *var_name = "test_var";
    const char *var_value = "test_value";
    ucl_parser_register_variable(parser, var_name, var_value);

    write_dummy_file(Data, Size);
    ucl_parser_set_filevars(parser, "./dummy_file", false);

    unsigned priority = Data[0] & 0x0F; // Use only 4 least significant bits
    enum ucl_duplicate_strategy strat = (enum ucl_duplicate_strategy)((Data[0] >> 4) % 4);
    enum ucl_parse_type parse_type = (enum ucl_parse_type)((Data[0] >> 6) % 4);

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ucl_parser_add_chunk_full
    ucl_parser_add_chunk_full(parser, Data, -1, priority, strat, parse_type);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
