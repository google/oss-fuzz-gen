#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "pcap/pcap.h"

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    if (fwrite(data, 1, size, file) != size) {
        fclose(file);
        unlink(tmpl); // Clean up the temporary file
        return 0;
    }

    fflush(file);
    rewind(file);

    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap == NULL) {
        fclose(file);
        unlink(tmpl); // Clean up the temporary file
        return 0;
    }

    pcap_dumper_t *dumper = pcap_dump_fopen(pcap, file);
    if (dumper == NULL) {
        pcap_close(pcap);
        fclose(file);
        unlink(tmpl); // Clean up the temporary file
        return 0;
    }

    // Remove the fclose(file) here as pcap_dump_fopen takes ownership of the file pointer
    int64_t position = pcap_dump_ftell64(dumper);

    pcap_dump_close(dumper);
    pcap_close(pcap);
    // Remove the temporary file after use
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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
