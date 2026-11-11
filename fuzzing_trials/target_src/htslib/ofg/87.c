#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <htslib/hts.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for close() and unlink()

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a valid filename
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as htsFile
    char tmp_filename[] = "/tmp/fuzzhtsXXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0;
    }
    FILE *tmp_file = fdopen(fd, "w+");
    if (!tmp_file) {
        close(fd);
        return 0;
    }

    // Initialize an htsFile structure
    htsFile *hts_fp = hts_open(tmp_filename, "w");
    if (!hts_fp) {
        fclose(tmp_file);
        return 0;
    }

    // Create a filename from the fuzz data
    char *filename = (char *)malloc(size + 1);
    if (!filename) {
        hts_close(hts_fp);
        fclose(tmp_file);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';  // Null-terminate the filename

    // Call the function-under-test
    hts_set_fai_filename(hts_fp, filename);

    // Clean up
    free(filename);
    hts_close(hts_fp);
    fclose(tmp_file);
    unlink(tmp_filename);

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

    LLVMFuzzerTestOneInput_87(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
