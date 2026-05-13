#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "htslib/hfile.h" // Correct path for hfile.h

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    if (size < sizeof(off_t) + sizeof(int)) {
        return 0; // Not enough data to extract required parameters
    }

    // Create a temporary file to use with hFILE
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0; // Failed to create a temporary file
    }

    // Write data to the temporary file
    fwrite(data, 1, size, temp_file);
    fflush(temp_file);

    // Rewind the file to the beginning
    rewind(temp_file);

    // Open the temporary file as an hFILE using hopen with a file descriptor
    char temp_filename[] = "/tmp/tempfileXXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        fclose(temp_file);
        return 0; // Failed to create a temporary file descriptor
    }

    hFILE *hfile = hopen(temp_filename, "r+");
    if (hfile == NULL) {
        close(fd);
        fclose(temp_file);
        return 0; // Failed to open as hFILE
    }

    // Extract off_t and int from data
    off_t offset = *(off_t *)(data);
    int whence = *(int *)(data + sizeof(off_t));

    // Call the function-under-test
    off_t result = hseek(hfile, offset, whence);

    // Clean up
    hclose(hfile);
    close(fd);
    fclose(temp_file);
    unlink(temp_filename); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
