#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // For mkstemp, write, close, remove
#include "/src/htslib/htslib/hfile.h" // Corrected path for hfile.h

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    hFILE *file = NULL;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);

    if (fd != -1) {
        // Write the fuzz data to the temporary file
        write(fd, data, size);
        close(fd);

        // Open the file using hFILE interface
        file = hopen(filename, "rb");
        if (file != NULL) {
            // Call the function-under-test
            hclose_abruptly(file);
        }

        // Remove the temporary file
        remove(filename);
    }

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

    LLVMFuzzerTestOneInput_99(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
