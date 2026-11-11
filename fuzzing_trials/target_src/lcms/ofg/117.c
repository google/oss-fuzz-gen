#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        cmsDeleteContext(context);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        cmsDeleteContext(context);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFileTHR(context, tmpl);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    unlink(tmpl);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_117(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
