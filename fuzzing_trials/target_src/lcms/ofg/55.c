#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <unistd.h> // Include for close() and remove()

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle;
    char **formatArray = NULL;

    // Create a temporary file to simulate a valid cmsHANDLE
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the file as a cmsHANDLE
    handle = cmsIT8LoadFromFile(0, tmpl);
    if (handle == NULL) {
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    cmsIT8EnumDataFormat(handle, &formatArray);

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

    LLVMFuzzerTestOneInput_55(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
