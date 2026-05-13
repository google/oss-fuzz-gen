#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    ucl_object_t *obj;

    // Ensure the data size is sufficient to create an object and set priority
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Create a new UCL object
    obj = ucl_object_new();

    // Extract an unsigned int from the data for the priority
    unsigned int priority = *(unsigned int *)data;

    // Call the function-under-test
    ucl_object_set_priority(obj, priority);

    // Clean up the UCL object
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

    LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
