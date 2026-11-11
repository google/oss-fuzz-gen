#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_349(const uint8_t *data, size_t size) {
    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Create a temporary file to simulate an IT8 file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        cmsIT8Free(handle);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        cmsIT8Free(handle);
        return 0;
    }
    close(fd);

    // Load the IT8 data from the temporary file into the cmsHANDLE
    if (!cmsIT8LoadFromFile(handle, tmpl)) {
        cmsIT8Free(handle);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number tableCount = cmsIT8TableCount(handle);

    // Clean up
    cmsIT8Free(handle);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_349(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
