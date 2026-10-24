#include <stdint.h>
#include <stdio.h>
#include <zlib.h>
#include <unistd.h>   // For mkstemp, close, and remove
#include <stdlib.h>   // For fdopen

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    gzFile file;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, f);
    fclose(f);

    // Open the file with gzopen
    file = gzopen(filename, "rb");
    if (file == NULL) {
        remove(filename);
        return 0;
    }

    int errnum;
    const char *error_message = gzerror(file, &errnum);

    // Use the error message and error number in some way
    if (error_message != NULL) {
        printf("Error message: %s, Error number: %d\n", error_message, errnum);
    }

    // Clean up
    gzclose(file);
    remove(filename);

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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
