#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of ucl_parser_new
    struct ucl_parser *parser = ucl_parser_new(-1);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_get_column to ucl_parser_add_fd_full
    // Ensure dataflow is valid (i.e., non-null)
    if (!parser) {
    	return 0;
    }
    const char* ret_ucl_parser_get_cur_file_tfayy = ucl_parser_get_cur_file(parser);
    if (ret_ucl_parser_get_cur_file_tfayy == NULL){
    	return 0;
    }
    int64_t ret_ucl_object_toint_cvgjt = ucl_object_toint(NULL);
    if (ret_ucl_object_toint_cvgjt < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!parser) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_toint to ucl_object_keyl
    ucl_object_t* ret_ucl_object_fromint_zbesj = ucl_object_fromint(64);
    if (ret_ucl_object_fromint_zbesj == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromint_zbesj) {
    	return 0;
    }
    const char* ret_ucl_object_keyl_zvxut = ucl_object_keyl(ret_ucl_object_fromint_zbesj, (size_t *)&ret_ucl_object_toint_cvgjt);
    if (ret_ucl_object_keyl_zvxut == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    bool ret_ucl_parser_add_fd_full_elhsw = ucl_parser_add_fd_full(parser, (int )column, (unsigned int )ret_ucl_object_toint_cvgjt, UCL_DUPLICATE_ERROR, UCL_PARSE_UCL);
    if (ret_ucl_parser_add_fd_full_elhsw == 0){
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
