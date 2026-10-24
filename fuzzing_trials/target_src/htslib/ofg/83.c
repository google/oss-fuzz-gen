#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include for close()
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    samFile *file = NULL;
    sam_hdr_t *header = NULL;
    int option = 0;

    if (size < 1) {
        return 0;
    }

    // Create a temporary file to simulate a samFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    file = sam_open(tmpl, "w");
    if (file == NULL) {
        perror("sam_open");
        close(fd);
        remove(tmpl);
        return 0;
    }

    // Initialize a sam_hdr_t structure
    header = sam_hdr_init();
    if (header == NULL) {
        perror("sam_hdr_init");
        sam_close(file);
        close(fd);
        remove(tmpl);
        return 0;
    }

    // Set the header text from the input data
    if (sam_hdr_add_lines(header, (const char *)data, size) != 0) {
        sam_hdr_destroy(header);
        sam_close(file);
        close(fd);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    sam_hdr_set(file, header, option);

    // Clean up
    sam_hdr_destroy(header);
    sam_close(file);
    close(fd);
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

    LLVMFuzzerTestOneInput_83(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
