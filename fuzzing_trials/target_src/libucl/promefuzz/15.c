// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_parser_new at ucl_parser.c:2826:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_parser_add_string at ucl_parser.c:3191:6 in ucl.h
// ucl_parser_get_error at ucl_util.c:665:1 in ucl.h
// ucl_parser_get_error at ucl_util.c:665:1 in ucl.h
// ucl_parser_get_object at ucl_util.c:590:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_object_compare at ucl_util.c:3733:5 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static ucl_object_t *create_test_object(void) {
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *nested = ucl_object_typed_new(UCL_STRING);
    nested->value.sv = strdup("test_value");
    nested->len = strlen(nested->value.sv);
    ucl_object_insert_key(obj, nested, "test_key", 0, false);
    return obj;
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a test UCL object
    ucl_object_t *obj = create_test_object();
    if (!obj) return 0;

    // Emit object to a string
    unsigned char *emitted = ucl_object_emit(obj, UCL_EMIT_JSON);
    if (emitted) {
        free(emitted);
    }

    // Create a new parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (!parser) {
        ucl_object_unref(obj);
        return 0;
    }

    // Add string to parser
    if (!ucl_parser_add_string(parser, (const char *)Data, Size)) {
        const char *error = ucl_parser_get_error(parser);
        if (error) {
            // Handle error if needed
        }
    }

    // Get error multiple times
    for (int i = 0; i < 3; i++) {
        const char *error = ucl_parser_get_error(parser);
        if (error) {
            // Handle error if needed
        }
    }

    // Get object from parser
    ucl_object_t *parsed_obj = ucl_parser_get_object(parser);
    if (parsed_obj) {
        // Unref the object
        ucl_object_unref(parsed_obj);
    }

    // Free the parser
    ucl_parser_free(parser);

    // Create another test UCL object for comparison
    ucl_object_t *obj2 = create_test_object();
    if (obj2) {
        // Compare objects
        int cmp_result = ucl_object_compare(obj, obj2);

        // Emit object to a string
        unsigned char *emitted2 = ucl_object_emit(obj2, UCL_EMIT_JSON);
        if (emitted2) {
            free(emitted2);
        }

        // Unref the second object
        ucl_object_unref(obj2);
    }

    // Unref the initial object after all operations
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
