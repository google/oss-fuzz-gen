#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a pointer-sized value
    if (size < sizeof(void *)) {
        return 0;
    }

    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Use the data as a void pointer
    void *pluginData = (void *)data;

    // Call the function-under-test
    cmsBool result = cmsPluginTHR(context, pluginData);

    // Clean up the context
    cmsDeleteContext(context);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_174(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
