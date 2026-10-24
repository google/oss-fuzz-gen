#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include this for mkstemp() and unlink()
#include <fcntl.h>   // Include this for open() and close()
#include <lcms2.h>

int LLVMFuzzerTestOneInput_421(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Initialize a cmsContext, assuming a default context for simplicity
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    cmsHANDLE handle = cmsIT8LoadFromFile(context, tmpl);

    // Clean up
    if (handle != NULL) {
        cmsIT8Free(handle);
    }
    cmsDeleteContext(context);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_421(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
