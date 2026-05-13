#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nMax = 0;
    cmsUInt32Number *codes = NULL;
    char **descriptions = NULL;

    // Ensure size is sufficient for at least one cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract cmsUInt32Number from data
    cmsUInt32Number intent = *(cmsUInt32Number *)data;

    // Allocate memory for codes and descriptions
    codes = (cmsUInt32Number *)malloc(sizeof(cmsUInt32Number) * 10); // Arbitrary size for testing
    descriptions = (char **)malloc(sizeof(char *) * 10);

    if (codes == NULL || descriptions == NULL) {
        if (codes) free(codes);
        if (descriptions) free(descriptions);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsGetSupportedIntentsTHR(context, intent, codes, descriptions);

    // Clean up
    free(codes);
    free(descriptions);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_180(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
