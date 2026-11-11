#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <unistd.h>  // Include for close and unlink
#include <fcntl.h>   // Include for mkstemp
#include "lcms2.h"

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to form a cmsFloat64Number
    }

    // Create a temporary file to store the profile data
    char tmpl[] = "/tmp/fuzzprofileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create temporary file
    }

    // Write the profile data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0; // Failed to write all data
    }
    close(fd);

    // Open the profile from the temporary file
    cmsHPROFILE hProfile = cmsOpenProfileFromFile(tmpl, "r");
    if (hProfile == NULL) {
        unlink(tmpl); // Remove the temporary file
        return 0; // Failed to open profile
    }

    // Use the first 8 bytes of data as a cmsFloat64Number
    cmsFloat64Number gammaValue;
    memcpy(&gammaValue, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number result = cmsDetectRGBProfileGamma(hProfile, gammaValue);

    // Clean up
    cmsCloseProfile(hProfile);
    unlink(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
