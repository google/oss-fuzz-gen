// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_new_int64 at json_object.c:799:21 in json_object.h
// json_object_get_int64 at json_object.c:819:9 in json_object.h
// json_object_int_inc at json_object.c:943:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_parse_int64 at json_util.c:243:5 in json_util.h
// json_parse_uint64 at json_util.c:260:5 in json_util.h
// json_type_to_name at json_util.c:307:13 in json_util.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <json_util.h>
#include <json_object.h>

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) {
        return 0;
    }

    int64_t input_int64;
    uint64_t input_uint64;
    memcpy(&input_int64, Data, sizeof(int64_t));
    memcpy(&input_uint64, Data, sizeof(uint64_t));

    // Test json_object_new_int64
    struct json_object *json_obj = json_object_new_int64(input_int64);
    if (json_obj) {
        // Test json_object_get_int64
        errno = 0;
        int64_t result_int64 = json_object_get_int64(json_obj);
        (void)result_int64; // Use result_int64 to avoid unused variable warning

        // Test json_object_int_inc
        json_object_int_inc(json_obj, input_int64);

        // Clean up
        json_object_put(json_obj);
    }

    // Test json_parse_int64
    char buffer[21]; // Enough to hold an int64_t as a string
    snprintf(buffer, sizeof(buffer), "%lld", (long long)input_int64);
    int64_t parsed_int64;
    errno = 0;
    json_parse_int64(buffer, &parsed_int64);

    // Test json_parse_uint64
    snprintf(buffer, sizeof(buffer), "%llu", (unsigned long long)input_uint64);
    uint64_t parsed_uint64;
    errno = 0;
    json_parse_uint64(buffer, &parsed_uint64);

    // Test json_type_to_name
    for (int i = json_type_null; i <= json_type_string; ++i) {
        const char *type_name = json_type_to_name((json_type)i);
        (void)type_name; // Use type_name to avoid unused variable warning
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

        LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    