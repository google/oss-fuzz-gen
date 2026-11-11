#include <gpac/isomedia.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    GF_ISOFile *file = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) {
        return 0;
    }

    Bool root_meta = GF_FALSE;
    u32 track_num = 1;

    // Create a temporary file for XMLFileName
    char tmpl[] = "/tmp/fuzz_xmlXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        gf_isom_close(file);
        return 0;
    }
    close(fd);

    // Write data to the temporary file
    FILE *xmlFile = fopen(tmpl, "wb");
    if (!xmlFile) {
        unlink(tmpl);
        gf_isom_close(file);
        return 0;
    }
    fwrite(data, 1, size, xmlFile);
    fclose(xmlFile);

    unsigned char *meta_data = (unsigned char *)malloc(size);
    if (!meta_data) {
        unlink(tmpl);
        gf_isom_close(file);
        return 0;
    }
    memcpy(meta_data, data, size);

    u32 data_size = size;
    Bool IsBinaryXML = GF_FALSE;

    // Call the function under test
    gf_isom_set_meta_xml(file, root_meta, track_num, tmpl, meta_data, data_size, IsBinaryXML);

    // Clean up
    unlink(tmpl);
    free(meta_data);
    gf_isom_close(file);

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
