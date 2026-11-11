#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ucl_object_t *create_dummy_ucl_object(const uint8_t *Data, size_t Size) {
    ucl_object_t *obj = malloc(sizeof(ucl_object_t));
    if (obj == NULL) {
        return NULL;
    }
    obj->key = (const char *)Data;
    obj->keylen = Size;
    obj->value.sv = (const char *)Data;
    obj->len = Size;  // Ensure length is set correctly for the string
    obj->type = UCL_STRING;
    return obj;
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    ucl_object_t *root = create_dummy_ucl_object(Data, Size);
    if (root == NULL) {
        return 0;
    }

    const char *key = "dummy_key";
    const ucl_object_t *lookup_result1 = ucl_object_lookup(root, key);
    const ucl_object_t *lookup_result2 = ucl_object_lookup(root, key);
    const ucl_object_t *lookup_result3 = ucl_object_lookup(root, key);

    struct ucl_schema_error err;
    bool is_valid = ucl_object_validate(root, root, &err);

    bool bool_value1 = ucl_object_toboolean(root);
    const char *string_value = ucl_object_tostring(root);
    bool bool_value2 = ucl_object_toboolean(root);

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ucl_object_emit
    unsigned char *json_output = ucl_object_emit(root, UCL_EMIT_MSGPACK);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_emit to ucl_parser_insert_chunk
    struct ucl_parser* ret_ucl_parser_new_xkqyr = ucl_parser_new(UCL_PRIORITY_MAX);
    if (ret_ucl_parser_new_xkqyr == NULL){
    	return 0;
    }
    unsigned int ret_ucl_array_size_vpaad = ucl_array_size(NULL);
    if (ret_ucl_array_size_vpaad < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_parser_new_xkqyr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!json_output) {
    	return 0;
    }
    bool ret_ucl_parser_insert_chunk_pwroj = ucl_parser_insert_chunk(ret_ucl_parser_new_xkqyr, json_output, (size_t )ret_ucl_array_size_vpaad);
    if (ret_ucl_parser_insert_chunk_pwroj == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    unsigned char *config_output = ucl_object_emit(root, UCL_EMIT_CONFIG);

    if (json_output) {
        free(json_output);
    }
    if (config_output) {
        free(config_output);
    }

    free(root);

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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
