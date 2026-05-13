#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsIOHANDLER *iohandler = NULL;
    FILE *tempFile = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Create a temporary file to write the fuzz data
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    tempFile = fdopen(fd, "wb+");
    if (tempFile == NULL) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (fwrite(data, 1, size, tempFile) != size) {
        fclose(tempFile);
        unlink(tmpl);
        return 0;
    }

    // Rewind the file to the beginning for reading
    rewind(tempFile);

    // Call the function-under-test
    iohandler = cmsOpenIOhandlerFromStream(context, tempFile);

    // Clean up
    if (iohandler != NULL) {
        cmsCloseIOhandler(iohandler);
    } else {
        fclose(tempFile);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
