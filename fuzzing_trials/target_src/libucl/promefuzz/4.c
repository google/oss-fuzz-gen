// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_emit_len at ucl_emitter.c:673:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_parser_new at ucl_parser.c:2826:1 in ucl.h
// ucl_parser_add_chunk_full at ucl_parser.c:2996:6 in ucl.h
// ucl_parser_get_error at ucl_util.c:665:1 in ucl.h
// ucl_parser_get_object at ucl_util.c:590:1 in ucl.h
// ucl_object_emit_len at ucl_emitter.c:673:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUMMY_FILE "./dummy_file"

static void write_to_dummy_file(const uint8_t *data, size_t size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Step 1: Create a new UCL object
    ucl_object_t *top = ucl_object_typed_new(UCL_OBJECT);
    if (!top) return 0;

    // Step 2: Insert key-value pairs into the UCL object
    ucl_object_t *elt1 = ucl_object_typed_new(UCL_INT);
    ucl_object_t *elt2 = ucl_object_typed_new(UCL_STRING);
    ucl_object_t *elt3 = ucl_object_typed_new(UCL_FLOAT);
    ucl_object_t *elt4 = ucl_object_typed_new(UCL_BOOLEAN);

    if (elt1 && elt2 && elt3 && elt4) {
        ucl_object_insert_key(top, elt1, "key1", 4, true);
        ucl_object_insert_key(top, elt2, "key2", 4, true);
        ucl_object_insert_key(top, elt3, "key3", 4, true);
        ucl_object_insert_key(top, elt4, "key4", 4, true);
    } else {
        ucl_object_unref(top);
        return 0;
    }

    // Step 3: Emit the UCL object to a string
    size_t emitted_len;
    unsigned char *emitted_str = ucl_object_emit_len(top, UCL_EMIT_JSON, &emitted_len);
    if (emitted_str) {
        free(emitted_str);
    }

    // Step 4: Unref the top-level UCL object
    ucl_object_unref(top);

    // Step 5: Create a new UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (!parser) return 0;

    // Step 6: Add data chunk to the parser
    if (Size > 0) {
        write_to_dummy_file(Data, Size);
        ucl_parser_add_chunk_full(parser, Data, Size, 0, UCL_DUPLICATE_APPEND, UCL_PARSE_UCL);
    }

    // Step 7: Get error if any
    const char *error = ucl_parser_get_error(parser);
    if (error) {
        // Handle error if needed
    }

    // Step 8: Retrieve the top-level object from the parser
    ucl_object_t *parsed_obj = ucl_parser_get_object(parser);
    if (parsed_obj) {
        // Step 9: Emit the parsed object to a string
        unsigned char *parsed_emitted_str = ucl_object_emit_len(parsed_obj, UCL_EMIT_JSON, &emitted_len);
        if (parsed_emitted_str) {
            free(parsed_emitted_str);
        }

        // Step 10: Unref the parsed object
        ucl_object_unref(parsed_obj);
    }

    // Step 11: Free the parser
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
