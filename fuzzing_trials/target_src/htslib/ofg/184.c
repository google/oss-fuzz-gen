#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    char tmpl1[] = "/tmp/fuzzfileXXXXXX";
    char tmpl2[] = "/tmp/fuzzmodeXXXXXX";
    int fd1 = mkstemp(tmpl1);
    int fd2 = mkstemp(tmpl2);

    if (fd1 == -1 || fd2 == -1) {
        return 0;
    }

    FILE *file1 = fdopen(fd1, "wb");
    FILE *file2 = fdopen(fd2, "wb");

    if (file1 == NULL || file2 == NULL) {
        close(fd1);
        close(fd2);
        return 0;
    }

    fwrite(data, 1, size, file1);
    fwrite(data, 1, size, file2);
    fclose(file1);
    fclose(file2);

    htsFile *hts_file = hts_open(tmpl1, tmpl2);

    if (hts_file != NULL) {
        hts_close(hts_file);
    }

    unlink(tmpl1);
    unlink(tmpl2);

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

    LLVMFuzzerTestOneInput_184(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
