#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // For close() and unlink()
#include <fcntl.h>  // For mkstemp()
#include <sys/types.h> // For ssize_t
#include <sys/stat.h> // For open()
#include "/src/htslib/htslib/hfile.h"

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a hFILE object
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Unable to create a temporary file
    }

    // Write the fuzz data to the temporary file
    ssize_t written = write(fd, data, size);
    if (written != size) {
        close(fd);
        unlink(tmpl);
        return 0; // Unable to write all data to the file
    }

    // Open the file as a hFILE object
    hFILE *hfile = hopen(tmpl, "rb");
    if (hfile == NULL) {
        close(fd);
        unlink(tmpl);
        return 0; // Unable to open the file as hFILE
    }

    // Perform read operation to increase code coverage
    char buffer[1024];
    ssize_t bytesRead = hread(hfile, buffer, sizeof(buffer));
    if (bytesRead < 0) {
        // Handle read error if necessary
    }

    // Close the hFILE object
    hclose(hfile);

    // Close the file descriptor and remove the temporary file
    close(fd);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_100(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
