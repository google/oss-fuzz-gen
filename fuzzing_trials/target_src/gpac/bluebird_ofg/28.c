#include <string.h>
#include <sys/stat.h>
#include "/src/gpac/include/gpac/isomedia.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include this for close() and remove()

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    GF_ISOFile *file;
    Bool root_meta;
    u32 track_num;
    u32 item_num;
    u32 itemID;
    u32 type;
    u32 protection_scheme;
    u32 protection_scheme_version;
    Bool is_self_reference;
    const char *item_name;
    const char *item_mime_type;
    const char *item_encoding;
    const char *item_url;
    const char *item_urn;

    // Create a temporary file to simulate an ISO file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);

    // Open the ISO file
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (!file) {
        remove(tmpl);
        return 0;
    }

    // Initialize parameters
    root_meta = 1; // or 0, depending on what you want to test
    track_num = 1; // Assuming at least one track
    item_num = 1;  // Assuming at least one item

    // Call the function under test
    gf_isom_get_meta_item_info(file, root_meta, track_num, item_num,
                               &itemID, &type, &protection_scheme, &protection_scheme_version, &is_self_reference,
                               &item_name, &item_mime_type, &item_encoding, &item_url, &item_urn);

    // Clean up
    gf_isom_close(file);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
