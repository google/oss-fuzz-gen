#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include this for close() and unlink()
#include <fcntl.h>  // Include this for mkstemp()
#include <lcms2.h>

int LLVMFuzzerTestOneInput_422(const uint8_t *data, size_t size) {
    cmsContext context = NULL; // Assuming a default context is acceptable
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    close(fd);

    // Call the function-under-test
    cmsHANDLE handle = cmsIT8LoadFromFile(context, tmpl);

    // Clean up
    if (handle != NULL) {
        cmsIT8Free(handle);
    }

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

    LLVMFuzzerTestOneInput_422(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
