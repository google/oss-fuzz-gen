#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_get_column to ucl_object_fromstring_common
    char *ugrydekb[1024] = {"avgkh", NULL};
    struct ucl_emitter_functions* ret_ucl_object_emit_memory_funcs_kndhl = ucl_object_emit_memory_funcs(ugrydekb);
    if (ret_ucl_object_emit_memory_funcs_kndhl == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ugrydekb) {
    	return 0;
    }
    ucl_object_t* ret_ucl_object_fromstring_common_wuukh = ucl_object_fromstring_common((const char *)*ugrydekb, (size_t )column, UCL_STRING_TRIM);
    if (ret_ucl_object_fromstring_common_wuukh == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    unsigned linenum = ucl_parser_get_linenum(parser);

    // Fuzz ucl_parser_clear_error
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
