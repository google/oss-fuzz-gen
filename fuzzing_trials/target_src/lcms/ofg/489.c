#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_489(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char label1[256];
    char label2[256];
    char label3[256];

    // Ensure size is sufficient to extract three labels
    if (size < 3) {
        return 0;
    }

    // Initialize labels with data, ensuring null-termination
    size_t label_length = size / 3;
    memcpy(label1, data, label_length);
    label1[label_length] = '\0';

    memcpy(label2, data + label_length, label_length);
    label2[label_length] = '\0';

    memcpy(label3, data + 2 * label_length, label_length);
    label3[label_length] = '\0';

    // Initialize a dummy cmsHANDLE (for fuzzing purposes only)
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsIT8SetTableByLabel(handle, label1, label2, label3);

    // Free the handle
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

    LLVMFuzzerTestOneInput_489(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
