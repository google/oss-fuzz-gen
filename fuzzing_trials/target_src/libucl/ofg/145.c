#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    if (size < sizeof(ucl_object_t) + sizeof(ucl_emitter_t) + sizeof(size_t)) {
        return 0; // Ensure there's enough data to create the required objects
    }

    // Initialize ucl_object_t
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    if (!obj) {
        return 0; // Handle allocation failure
    }

    // Initialize ucl_emitter_t
    ucl_emitter_t emitter = (ucl_emitter_t)(data[0] % 3); // Assuming there are 3 possible enum values

    // Initialize size_t
    size_t output_size = 0;

    // Call the function-under-test
    unsigned char *result = ucl_object_emit_len(obj, emitter, &output_size);

    // Free allocated resources
    if (result) {
        free(result);
    }
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
