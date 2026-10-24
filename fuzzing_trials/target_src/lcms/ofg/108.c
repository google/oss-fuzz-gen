#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Define temporary file template
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(tmpl);
        return 0; // If write fails, cleanup and exit
    }
    close(fd);

    // Define a mode for opening the profile
    const char *mode = "r"; // Read mode

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromFile(tmpl, mode);

    // Cleanup: remove the temporary file
    remove(tmpl);

    // If profile is opened, close it
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

    LLVMFuzzerTestOneInput_108(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
