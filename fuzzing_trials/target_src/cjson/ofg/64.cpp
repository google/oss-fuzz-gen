#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Parse the input data into a cJSON object
    cJSON *json = cJSON_ParseWithLength((const char *)data, size);
    if (json == NULL) return 0;

    // Allocate a buffer for preallocated printing
    int buffer_size = size + 100; // Some extra space for formatting
    char *buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        cJSON_Delete(json);
        return 0;
    }

    // Use the first byte of data to determine the preallocation flag
    cJSON_bool prealloc_flag = data[0] % 2 == 0 ? cJSON_True : cJSON_False;

    // Call the function-under-test
    cJSON_bool result = cJSON_PrintPreallocated(json, buffer, buffer_size, prealloc_flag);

    // Clean up
    free(buffer);
    cJSON_Delete(json);

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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
