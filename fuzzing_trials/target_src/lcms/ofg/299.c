#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_299(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context;
    cmsFloat64Number adaptationState;

    // Ensure size is sufficient to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the context
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the data
    adaptationState = *(const cmsFloat64Number *)data;

    // Call the function-under-test
    cmsSetAdaptationStateTHR(context, adaptationState);

    // Cleanup
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

    LLVMFuzzerTestOneInput_299(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
