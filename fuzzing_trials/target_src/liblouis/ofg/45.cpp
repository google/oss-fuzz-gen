#include <stdint.h>
#include <stddef.h>

extern "C" {
    // Include the header where lou_version is declared
    const char * lou_version();
}

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version = lou_version();

    // Use the version string in some way to prevent compiler optimizations
    if (version != nullptr) {
        // Print or log the version string (in a real fuzzing scenario, you might not do this)
        // but here we ensure the string is used
        volatile const char *used_version = version;
        (void)used_version; // Avoid unused variable warning
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
