#include <pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;
    pcap_dumper_t *dumper = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure the size is reasonable
    if (size < sizeof(struct pcap_file_header)) {
        return 0;
    }

    // Create a temporary file to pass as the filename
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Write data to the temporary file
    FILE *file = fopen(tmpl, "wb");
    if (file == NULL) {
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open a live capture handle for any available device
    pcap_handle = pcap_open_dead(DLT_EN10MB, BUFSIZ);
    if (pcap_handle == NULL) {
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    dumper = pcap_dump_open(pcap_handle, tmpl);
    if (dumper == NULL) {
        pcap_close(pcap_handle);
        remove(tmpl);
        return 0;
    }

    // Read the data back from the file and process it
    file = fopen(tmpl, "rb");
    if (file != NULL) {
        uint8_t buffer[BUFSIZ];
        size_t bytes_read;
        struct pcap_pkthdr header;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            header.caplen = bytes_read;
            header.len = bytes_read;
            pcap_dump((u_char *)dumper, &header, buffer);
        }
        fclose(file);
    }

    // Clean up
    pcap_dump_close(dumper);
    pcap_close(pcap_handle);
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
