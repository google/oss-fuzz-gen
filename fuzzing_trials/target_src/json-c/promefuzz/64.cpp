// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_from_file at json_util.c:145:21 in json_util.h
// json_object_new_string_len at json_object.c:1357:21 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_object_add at json_object.c:594:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_object_add_ex at json_object.c:557:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_object_del at json_object.c:638:6 in json_object.h
// json_object_to_json_string_ext at json_object.c:434:13 in json_object.h
// json_object_to_json_string_length at json_object.c:408:13 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <json_util.h>
#include <json_object.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>

static void create_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a dummy file for json_object_from_file
    create_dummy_file(Data, Size);

    // Attempt to read json_object from file
    struct json_object *json_obj = json_object_from_file("./dummy_file");
    if (json_obj == NULL) return 0;

    // Prepare a key and a value
    const char *key = "fuzz_key";
    struct json_object *val = json_object_new_string_len((const char *)Data, Size);
    if (!val) {
        json_object_put(json_obj);
        return 0;
    }

    // Test json_object_object_add
    if (json_object_object_add(json_obj, key, val) != 0) {
        json_object_put(val);  // Manually release if add fails
    }

    // Test json_object_object_add_ex
    if (json_object_object_add_ex(json_obj, key, val, 0) != 0) {
        json_object_put(val);  // Manually release if add_ex fails
    }

    // Test json_object_object_del
    json_object_object_del(json_obj, key);

    // Test json_object_to_json_string_ext
    const char *json_str_ext = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);

    // Test json_object_to_json_string_length
    size_t length;
    const char *json_str_length = json_object_to_json_string_length(json_obj, JSON_C_TO_STRING_PRETTY, &length);

    // Cleanup
    json_object_put(json_obj);

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

        LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    