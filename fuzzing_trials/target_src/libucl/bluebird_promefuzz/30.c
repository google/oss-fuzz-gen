#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Simulate parsing input data
    if (Size > 0) {
        FILE *file = fopen("./dummy_file", "wb");
        if (file != NULL) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            ucl_parser_add_file(parser, "./dummy_file");
        }
    }

    // Fuzz ucl_parser_get_column
    unsigned column = ucl_parser_get_column(parser);

    // Fuzz ucl_parser_get_linenum
    unsigned linenum = ucl_parser_get_linenum(parser);

    // Fuzz ucl_parser_clear_error

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_get_linenum to ucl_object_reserve
    // Ensure dataflow is valid (i.e., non-null)
    if (!parser) {
    	return 0;
    }
    ucl_object_t* ret_ucl_parser_get_object_ihtup = ucl_parser_get_object(parser);
    if (ret_ucl_parser_get_object_ihtup == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_parser_get_object_ihtup) {
    	return 0;
    }
    bool ret_ucl_object_reserve_ftmkz = ucl_object_reserve(ret_ucl_parser_get_object_ihtup, (size_t )linenum);
    if (ret_ucl_object_reserve_ftmkz == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    ucl_parser_clear_error(parser);

    // Fuzz ucl_parser_get_error_code
    int error_code = ucl_parser_get_error_code(parser);

    // Fuzz ucl_parser_get_object
    ucl_object_t *obj = ucl_parser_get_object(parser);

    // Fuzz ucl_object_unref only if obj is not NULL
    if (obj != NULL) {
        ucl_object_unref(obj);
    }

    // Fuzz ucl_parser_free
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
