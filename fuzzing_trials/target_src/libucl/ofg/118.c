#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Define UCL_TYPE_MAX if it's not defined in the ucl.h
#ifndef UCL_TYPE_MAX
#define UCL_TYPE_MAX 10 // Assuming 10 is the maximum value for ucl_type_t, adjust as necessary
#endif

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract the necessary parameters
    if (size < sizeof(ucl_type_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract the ucl_type_t from the data
    ucl_type_t type = (ucl_type_t)(data[0] % UCL_TYPE_MAX); // Ensure valid ucl_type_t

    // Extract the unsigned int from the data
    unsigned int priority = *((unsigned int *)(data + 1));

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_new_full(type, priority);

    // Clean up
    if (obj != NULL) {
        ucl_object_unref(obj);
    }

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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
