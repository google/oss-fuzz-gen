#include <sys/stat.h>
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
#include "/src/json-c/json_util.h"
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a buffer for string parsing
    char buffer[Size + 1];
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';

    // Fuzz json_object_new_int64
    int64_t int64_input;
    if (Size >= sizeof(int64_t)) {
        memcpy(&int64_input, Data, sizeof(int64_t));
        struct json_object *int64_obj = json_object_new_int64(int64_input);
        if (int64_obj) {
            json_object_put(int64_obj);
        }
    }

    // Fuzz json_object_new_uint64
    uint64_t uint64_input;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&uint64_input, Data, sizeof(uint64_t));
        struct json_object *uint64_obj = json_object_new_uint64(uint64_input);
        if (uint64_obj) {
            json_object_put(uint64_obj);
        }
    }

    // Fuzz json_parse_uint64
    uint64_t parsed_uint64;
    json_parse_uint64(buffer, &parsed_uint64);

    // Fuzz json_object_set_uint64
    struct json_object *uint64_obj_set = json_object_new_uint64(0);
    if (uint64_obj_set) {
        json_object_set_uint64(uint64_obj_set, uint64_input);
        json_object_put(uint64_obj_set);
    }

    // Fuzz json_object_get_int64
    struct json_object *int64_obj_get = json_object_new_int64(0);
    if (int64_obj_get) {
        errno = 0;
        json_object_get_int64(int64_obj_get);
        json_object_put(int64_obj_get);
    }

    // Fuzz json_object_get_uint64
    struct json_object *uint64_obj_get = json_object_new_uint64(0);
    if (uint64_obj_get) {
        errno = 0;
        json_object_get_uint64(uint64_obj_get);
        json_object_put(uint64_obj_get);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
