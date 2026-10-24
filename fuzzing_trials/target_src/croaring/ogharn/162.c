#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_162(char *fuzzData, size_t size)
{
	

   roaring_array_t ra_portable_deserializeoverload1var0;
	memset(&ra_portable_deserializeoverload1var0, 0, sizeof(ra_portable_deserializeoverload1var0));

   size_t ra_portable_deserializeoverload1var3 = 1;
   bool ra_portable_deserializeoverload1val1 = ra_portable_deserialize(&ra_portable_deserializeoverload1var0, fuzzData, size, &ra_portable_deserializeoverload1var3);
   ra_clear_containers(&ra_portable_deserializeoverload1var0);
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

        LLVMFuzzerTestOneInput_162(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    