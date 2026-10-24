#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for creating a cmsMLU object
    if (size < 4) {
        return 0;
    }

    // Create a cmsMLU object using the input data
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) {
        return 0;
    }

    // Use the input data to set some dummy values in the cmsMLU object
    char language[3] = { (char)data[0], (char)data[1], '\0' };
    char country[3] = { (char)data[2], (char)data[3], '\0' };
    cmsMLUsetASCII(mlu, language, country, "Test String");

    // Call the function-under-test
    cmsMLU *duplicatedMlu = cmsMLUdup(mlu);

    // Clean up
    cmsMLUfree(mlu);
    if (duplicatedMlu) {
        cmsMLUfree(duplicatedMlu);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_91(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
