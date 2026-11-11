#include <stdio.h>
#include <stdint.h>
#include <unistd.h>      // For close() and unlink()
#include <fcntl.h>       // For mkstemp()
#include <sys/types.h>   // For ssize_t
#include <sys/stat.h>    // For open()
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    GF_ISOFile *file = NULL;
    Bool root_meta = 1;  // Initialize to true
    u32 track_num = 1;   // Initialize to a valid track number
    char outName[] = "output.xml";  // Output file name
    Bool is_binary = 0;  // Initialize to false

    // Create a temporary file to simulate an ISO media file for testing
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

    // Open the temporary file as an ISO media file
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_extract_meta_xml(file, root_meta, track_num, outName, &is_binary);

    // Clean up
    gf_isom_close(file);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
