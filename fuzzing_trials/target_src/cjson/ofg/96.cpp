#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Added to include malloc and free
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    const char *parse_end = NULL;
    cJSON_bool require_null_termination = cJSON_True; // or cJSON_False, try both

    // Ensure the input data is NULL-terminated
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) {
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Call the function-under-test
    cJSON *json = cJSON_ParseWithLengthOpts(input_data, size, &parse_end, require_null_termination);

    // Clean up
    if (json != NULL) {
        cJSON_Delete(json);
    }
    free(input_data);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
