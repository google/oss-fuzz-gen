#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the temporary file with gzopen
    gzFile file = gzopen(tmpl, "rb");
    if (file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Prepare a buffer to read data
    char buffer[1024];
    int bytesRead;

    // Attempt to read from the gzFile
    while ((bytesRead = gzread(file, buffer, sizeof(buffer))) > 0) {
        // Process the data if needed
    }

    // Prepare the error code variable
    int errnum = 0;

    // Call the function-under-test
    const char *error = gzerror(file, &errnum);

    // Clean up
    gzclose(file);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
