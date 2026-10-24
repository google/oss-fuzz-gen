#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_252(char *fuzzData, size_t size)
{
	

   size_t janet_unmarshalvar1 = 1;
   uint8_t janet_scan_int64var0;
	memset(&janet_scan_int64var0, 0, sizeof(janet_scan_int64var0));

   int64_t janet_scan_int64var2;
	memset(&janet_scan_int64var2, 0, sizeof(janet_scan_int64var2));

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_getargindexval1 = janet_getargindex(&janet_wrap_nilval1, JANET_TFLAG_INDEXED, janet_initval1, fuzzData);
	if((int)janet_getargindexval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   Janet janet_unmarshalval1 = janet_unmarshal(&janet_symbol_genval1, janet_unmarshalvar1, janet_getargindexval1, NULL, &fuzzData);
   int janet_gcunrootval1 = janet_gcunroot(janet_unmarshalval1);
	if((int)janet_gcunrootval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int janet_scan_int64val1 = janet_scan_int64(&janet_scan_int64var0, janet_gcunrootval1, &janet_scan_int64var2);
	if((int)janet_scan_int64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
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

        LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    