#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Rewind the file to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file with gzopen
    FILE *file = fdopen(fd, "rb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    gzFile gzfile = gzdopen(fd, "rb");
    if (gzfile == NULL) {
        fclose(file);
        return 0;
    }

    // Perform some operations on the gzfile to exercise the function under test
    char buffer[1024];
    while (gzread(gzfile, buffer, sizeof(buffer)) > 0) {
        // Read through the file to change the state
    }

    // Call the function-under-test
    off_t offset = gzoffset(gzfile);

    // Clean up
    gzclose(gzfile);
    fclose(file);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
