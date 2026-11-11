#include <string.h>
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
extern "C" {
#include "../cJSON.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static cJSON* safe_create_object() {
    cJSON* object = cJSON_CreateObject();
    return object ? object : nullptr;
}

static cJSON* safe_add_null_to_object(cJSON* object, const char* name) {
    return cJSON_AddNullToObject(object, name);
}

static void safe_delete(cJSON* item) {
    if (item) {
        cJSON_Delete(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Prepare a null-terminated string for the key name.
    size_t key_length = Size < 256 ? Size : 255;
    char key_name[256];
    memcpy(key_name, Data, key_length);
    key_name[key_length] = '\0';

    // Create a JSON object.
    cJSON* json_object = safe_create_object();
    if (!json_object) {
        return 0;
    }

    // Attempt to add a null item to the object with the given key name.
    cJSON* null_item = safe_add_null_to_object(json_object, key_name);

    // Clean up the JSON object regardless of success or failure.
    safe_delete(json_object);

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
