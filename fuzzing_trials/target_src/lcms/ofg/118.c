#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Function to create a temporary file with the given data
static char* create_temp_file(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return NULL;
    }

    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        return NULL;
    }

    close(fd);
    return strdup(tmpl);
}

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a temporary file with the fuzz data
    char *filename = create_temp_file(data, size);
    if (filename == NULL) {
        return 0;
    }

    // Initialize a cmsContext (using NULL for default context)
    cmsContext context = NULL;

    // Call the function under test
    cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFileTHR(context, filename);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    remove(filename);
    free(filename);

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

    LLVMFuzzerTestOneInput_118(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
