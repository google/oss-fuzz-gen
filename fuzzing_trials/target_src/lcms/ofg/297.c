#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_297(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *set;
    const char *field;
    
    // Ensure the data size is sufficient for the strings
    if (size < 2) {
        return 0;
    }

    // Initialize the handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);

    // Split the data into two parts for set and field
    size_t set_size = size / 2;
    size_t field_size = size - set_size;

    // Allocate memory for set and field, ensuring null termination
    char *set_buf = (char *)malloc(set_size + 1);
    char *field_buf = (char *)malloc(field_size + 1);

    if (set_buf == NULL || field_buf == NULL) {
        free(set_buf);
        free(field_buf);
        cmsIT8Free(handle);
        return 0;
    }

    // Copy data into set and field buffers
    memcpy(set_buf, data, set_size);
    memcpy(field_buf, data + set_size, field_size);

    // Null terminate the strings
    set_buf[set_size] = '\0';
    field_buf[field_size] = '\0';

    // Assign set and field to the buffers
    set = set_buf;
    field = field_buf;

    // Call the function-under-test
    cmsFloat64Number result = cmsIT8GetDataDbl(handle, set, field);

    // Clean up
    free(set_buf);
    free(field_buf);
    cmsIT8Free(handle);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_297(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
