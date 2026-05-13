#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include this header for the close() and unlink() functions

// Function to create a temporary file with the given data
static char *create_temp_file(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return NULL;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return NULL;
    }
    fwrite(data, 1, size, file);
    fclose(file);
    return strdup(tmpl);
}

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;
    char *filename = NULL;

    if (size == 0) {
        return 0;
    }

    // Create a temporary file with the fuzzing data
    filename = create_temp_file(data, size);
    if (!filename) {
        return 0;
    }

    // Call the function-under-test
    pcap_handle = pcap_open_offline(filename, errbuf);

    // Clean up
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
    }
    unlink(filename);
    free(filename);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
