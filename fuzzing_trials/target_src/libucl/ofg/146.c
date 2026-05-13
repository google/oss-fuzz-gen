#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>  // Include for memory management functions like free
#include "/src/libucl/include/ucl.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Initialize necessary variables
    ucl_object_t *obj;
    ucl_emitter_t emitter_type = UCL_EMIT_JSON; // Example emitter type
    size_t emitted_len = 0;
    unsigned char *result;

    // Check if the input size is sufficient to create a UCL object
    if (size == 0) {
        return 0;
    }

    // Create a UCL object from the input data
    obj = ucl_object_fromstring((const char *)data);

    // Ensure the object is not NULL
    if (obj == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = ucl_object_emit_len(obj, emitter_type, &emitted_len);

    // Free the UCL object
    ucl_object_unref(obj);

    // Free the result if it was allocated
    if (result != NULL) {
        free(result);  // Use standard free function instead of ucl_free
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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
