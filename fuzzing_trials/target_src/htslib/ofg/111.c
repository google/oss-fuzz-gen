#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for mkstemp, write, close, unlink
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate an htsFile input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the temporary file as an htsFile
    htsFile *file = hts_open(tmpl, "r");
    if (file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    const htsFormat *format = hts_get_format(file);

    // Clean up
    hts_close(file);
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

    LLVMFuzzerTestOneInput_111(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
