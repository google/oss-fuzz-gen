#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for rand()

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"

    // Declaration of the function-under-test
    unsigned char * tjAlloc(int size);
    void tjFree(unsigned char *buffer);
}

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Define an integer for the size parameter
    int allocSize;

    // Ensure that the size is not zero to avoid tjAlloc(0) which might return NULL
    if (size > 0) {
        // Use the first byte of data to determine the size for tjAlloc
        allocSize = static_cast<int>(data[0]);

        // Ensure allocSize is reasonable to avoid tjAlloc returning NULL
        // Set a minimum size to ensure meaningful allocation
        if (allocSize < 1) {
            allocSize = 1;
        }

        // Call the function-under-test
        unsigned char *allocatedMemory = tjAlloc(allocSize);

        // Free the allocated memory if it's not NULL
        if (allocatedMemory != NULL) {
            // Optionally, use the allocated memory to ensure it's not optimized away
            allocatedMemory[0] = 0;  // Simple operation to use the memory
            tjFree(allocatedMemory);
        }
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
