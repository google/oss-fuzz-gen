#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    if (size < sizeof(cJSON_Hooks)) {
        return 0;
    }

    cJSON_Hooks hooks;
    memcpy(&hooks, data, sizeof(cJSON_Hooks));

    // Ensure that the malloc and free hooks are not NULL
    if (hooks.malloc_fn == NULL) {
        hooks.malloc_fn = malloc;
    }
    if (hooks.free_fn == NULL) {
        hooks.free_fn = free;
    }

    cJSON_InitHooks(&hooks);

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
