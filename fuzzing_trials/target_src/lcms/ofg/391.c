#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for mkstemp() and close()
#include <fcntl.h>  // Include for write()
#include <lcms2.h>

int LLVMFuzzerTestOneInput_391(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure the data size is sufficient to create a profile
    if (size < 128) { // 128 is an arbitrary minimum size for a valid profile
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open a profile from the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsSaveProfileToFile(hProfile, tmpl);

    // Close the profile
    cmsCloseProfile(hProfile);

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_391(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
