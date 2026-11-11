#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If we can't create a temp file, exit early
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl); // Remove the file
        return 0; // If write fails, exit early
    }

    // Close the file descriptor
    close(fd);

    // Call the function-under-test with the temporary file path
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFile(tmpl);

    // Clean up: unlink the temporary file
    unlink(tmpl);

    // If a profile was created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_162(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
