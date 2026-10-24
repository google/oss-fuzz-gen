#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "/src/json-c/json_util.h"
#include "/src/json-c/json_object.h"
#include <errno.h>
}

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // 1. Fuzz json_object_new_int64
    int64_t int64_input;
    if (Size >= sizeof(int64_t)) {
        memcpy(&int64_input, Data, sizeof(int64_t));
        struct json_object *obj = json_object_new_int64(int64_input);
        if (obj) {
            json_object_put(obj); // Cleanup
        }
    }

    // 2. Fuzz json_object_get_int64
    struct json_object *int_obj = json_object_new_int64(0); // Create a dummy object
    if (int_obj) {
        errno = 0;
        json_object_get_int64(int_obj);
        json_object_put(int_obj); // Cleanup
    }

    // 3. Fuzz json_parse_int64
    char *str_input = new char[Size + 1];
    memcpy(str_input, Data, Size);
    str_input[Size] = '\0'; // Null-terminate
    int64_t parsed_value;
    json_parse_int64(str_input, &parsed_value);
    delete[] str_input; // Cleanup

    // 4. Fuzz json_parse_uint64
    // Ensure null-termination for safe string operations
    char *u_str_input = new char[Size + 1];
    memcpy(u_str_input, Data, Size);
    u_str_input[Size] = '\0'; // Null-terminate
    uint64_t parsed_uvalue;
    json_parse_uint64(u_str_input, &parsed_uvalue);
    delete[] u_str_input; // Cleanup

    // 5. Fuzz json_object_int_inc
    struct json_object *inc_obj = json_object_new_int64(0); // Create a dummy object
    if (inc_obj) {
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function json_object_int_inc with json_object_set_int64
        json_object_set_int64(inc_obj, int64_input);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        json_object_put(inc_obj); // Cleanup
    }

    // 6. Fuzz json_type_to_name
    enum json_type types[] = {
        json_type_null, json_type_boolean, json_type_double,
        json_type_int, json_type_object, json_type_array, json_type_string
    };
    for (auto type : types) {
        json_type_to_name(type);
    }

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
