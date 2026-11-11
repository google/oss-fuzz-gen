#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>  // Include for close() and unlink()
#include <fcntl.h>   // Include for mkstemp()
#include <lcms2.h>

int LLVMFuzzerTestOneInput_342(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Create a temporary file to hold the profile data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);  // Use unlink instead of remove for POSIX compliance
        return 0;
    }
    close(fd);

    // Open the profile from the file
    hProfile = cmsOpenProfileFromFile(tmpl, "r");
    if (hProfile == NULL) {
        // Clean up the temporary file
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number version = cmsGetEncodedICCversion(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);
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

    LLVMFuzzerTestOneInput_342(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
