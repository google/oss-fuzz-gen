#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a ucl_object_t
    if (size < sizeof(ucl_object_t)) {
        return 0;
    }
    
    // Create a ucl_object_t from the input data
    ucl_object_t obj;
    obj.key = NULL; // Assuming key is not needed for this test
    obj.value.iv = *(int64_t *)data; // Treat the first 8 bytes as an integer value
    obj.type = UCL_INT; // Set the type to integer

    // Call the function-under-test
    int64_t result = ucl_object_toint(&obj);

    // Use the result to avoid any compiler optimizations that might skip the function call
    (void)result;

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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
