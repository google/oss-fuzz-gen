#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Dummy packet handler function
void packet_handler_115(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    (void)h;
    (void)bytes;
}

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char user_data[1] = {0}; // Dummy user data

    // Create a temporary file to simulate a pcap file
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file pointer to the beginning of the file
    rewind(temp_file);

    // Open the temporary file as a pcap file
    pcap = pcap_fopen_offline(temp_file, errbuf);
    if (pcap == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Call the function-under-test
    pcap_loop(pcap, 0, packet_handler_115, user_data);

    // Clean up
    pcap_close(pcap);
    fclose(temp_file);

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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
