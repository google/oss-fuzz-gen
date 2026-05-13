#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract required inputs
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Create a ucl_object_t object
    ucl_object_t *obj = ucl_object_new();

    // Extract an unsigned int from the data
    unsigned int priority = *(unsigned int *)data;

    // Call the function-under-test
    ucl_object_set_priority(obj, priority);

    // Clean up
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

    LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
