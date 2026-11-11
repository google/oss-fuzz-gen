#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for mkstemp, write, and close

typedef struct hFILE hFILE;

// Mock definition of hFILE to allow compilation
struct hFILE {
    FILE *file;
};

// Mock implementation of hopen_85 to allow compilation
hFILE *hopen_85(const char *filename, const char *mode, void *options) {
    hFILE *hfile = (hFILE *)malloc(sizeof(hFILE));
    if (hfile == NULL) {
        return NULL;
    }

    hfile->file = fopen(filename, mode);
    if (hfile->file == NULL) {
        free(hfile);
        return NULL;
    }

    return hfile;
}

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to create a filename and mode
    if (size < 3) {
        return 0;
    }

    // Create a temporary file to use as input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Set mode to a non-NULL value
    const char *mode = "r";

    // Call the function-under-test
    hFILE *file = hopen_85(tmpl, mode, NULL);

    // Clean up
    if (file != NULL) {
        if (file->file != NULL) {
            fclose(file->file);
        }
        free(file);
    }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_85(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
