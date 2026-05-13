#include <stdint.h>
#include <stdlib.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cJSON *json_array = cJSON_CreateArray();

    // If the array was created successfully, perform further operations
    if (json_array != NULL) {
        // Since this is a fuzz test, we don't have specific data to add to the array.
        // Normally, you would add items to the array here if needed.

        // Clean up by deleting the created JSON array
        cJSON_Delete(json_array);
    }

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
