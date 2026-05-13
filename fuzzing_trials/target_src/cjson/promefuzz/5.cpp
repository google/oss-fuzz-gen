// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_ParseWithOpts at cJSON.c:1131:23 in cJSON.h
// cJSON_PrintBuffered at cJSON.c:1317:22 in cJSON.h
// cJSON_Minify at cJSON.c:2924:20 in cJSON.h
// cJSON_free at cJSON.c:3202:20 in cJSON.h
// cJSON_Print at cJSON.c:1307:22 in cJSON.h
// cJSON_free at cJSON.c:3202:20 in cJSON.h
// cJSON_PrintUnformatted at cJSON.c:1312:22 in cJSON.h
// cJSON_free at cJSON.c:3202:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
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
#include "cJSON.h"
}

#include <cstddef>
#include <cstdint>
#include <cstring>

static void handle_cjson_operations(const char *json, size_t size) {
    const char *end_ptr = nullptr;
    cJSON *parsed_json = cJSON_ParseWithOpts(json, &end_ptr, cJSON_True);

    if (parsed_json == nullptr) {
        return;
    }

    char *buffered_output = cJSON_PrintBuffered(parsed_json, 256, cJSON_True);
    if (buffered_output) {
        cJSON_Minify(buffered_output);
        cJSON_free(buffered_output);
    }

    char *formatted_output = cJSON_Print(parsed_json);
    if (formatted_output) {
        cJSON_free(formatted_output);
    }

    char *unformatted_output = cJSON_PrintUnformatted(parsed_json);
    if (unformatted_output) {
        cJSON_free(unformatted_output);
    }

    cJSON_Delete(parsed_json);
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    char *json = static_cast<char *>(malloc(Size + 1));
    if (json == nullptr) {
        return 0;
    }

    memcpy(json, Data, Size);
    json[Size] = '\0';

    handle_cjson_operations(json, Size);

    free(json);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
