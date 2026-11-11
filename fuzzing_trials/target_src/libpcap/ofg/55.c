#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>  // For close()

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    FILE *tempFile;
    char tempFileName[] = "/tmp/fuzzfileXXXXXX";
    pcap_t *pcapHandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create a temporary file and write the fuzz data to it
    int fd = mkstemp(tempFileName);
    if (fd == -1) {
        return 0;
    }
    
    tempFile = fdopen(fd, "wb");
    if (!tempFile) {
        close(fd);
        return 0;
    }
    
    fwrite(data, 1, size, tempFile);
    fclose(tempFile);

    // Reopen the file for reading
    tempFile = fopen(tempFileName, "rb");
    if (!tempFile) {
        return 0;
    }

    // Call the function-under-test
    pcapHandle = pcap_fopen_offline(tempFile, errbuf);

    // Clean up
    if (pcapHandle != NULL) {
        pcap_close(pcapHandle);
    }
    fclose(tempFile);
    remove(tempFileName);

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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
