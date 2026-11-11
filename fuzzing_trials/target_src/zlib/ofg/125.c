#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdio.h>
#include <unistd.h> // Include for close() and remove()
#include <sys/types.h> // Include for off64_t

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to write the fuzzing data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file with gzopen
    gzFile gz_file = gzopen(tmpl, "rb");
    if (gz_file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Read some data from the gzFile to change the position
    char buffer[1024];
    int bytes_read = gzread(gz_file, buffer, sizeof(buffer));

    // Call the function-under-test
    z_off_t position = gztell64(gz_file);

    // Output the position for debugging purposes (optional)
    printf("Current position in the uncompressed stream: %lld\n", (long long)position);

    // Clean up
    gzclose(gz_file);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
