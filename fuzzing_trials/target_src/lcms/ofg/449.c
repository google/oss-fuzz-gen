#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // Include for close() and unlink()

extern long cmsfilelength(FILE *);

int LLVMFuzzerTestOneInput_449(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    FILE *file = fdopen(fd, "wb+");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the file
    if (fwrite(data, 1, size, file) != size) {
        fclose(file);
        unlink(tmpl); // Use unlink instead of remove for temporary files
        return 0;
    }

    // Rewind the file to the beginning for reading
    rewind(file);

    // Call the function-under-test
    long length = cmsfilelength(file);

    // Optionally, you can add some checks or assertions here to verify the output
    // For example, you might want to check if length is within expected bounds

    // Cleanup
    fclose(file);
    unlink(tmpl); // Use unlink instead of remove for temporary files

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

    LLVMFuzzerTestOneInput_449(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
