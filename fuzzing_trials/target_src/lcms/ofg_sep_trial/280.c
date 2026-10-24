#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_280(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    const char *language = "en";
    const char *country = "US";
    char buffer[256];
    char fallback[256];

    // Ensure that the data size is sufficient
    if (size < 1) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Copy data to buffer and fallback, ensuring null-termination
    size_t copy_size = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, copy_size);
    buffer[copy_size] = '\0';

    copy_size = size < sizeof(fallback) - 1 ? size : sizeof(fallback) - 1;
    memcpy(fallback, data, copy_size);
    fallback[copy_size] = '\0';

    // Call the function-under-test
    cmsBool result = cmsMLUgetTranslation(mlu, language, country, buffer, fallback);

    // Clean up
    cmsMLUfree(mlu);

    return 0;
}