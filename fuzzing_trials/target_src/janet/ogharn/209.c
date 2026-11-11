#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_209(char *fuzzData, size_t size)
{
	

   size_t janet_unmarshalvar1 = 1;
   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_getargindexval1 = janet_getargindex(&janet_wrap_nilval1, JANET_TFLAG_INDEXED, janet_initval1, fuzzData);
	if((int)janet_getargindexval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   Janet janet_unmarshalval1 = janet_unmarshal(&janet_symbol_genval1, janet_unmarshalvar1, janet_getargindexval1, NULL, &fuzzData);
   int janet_checksizeval1 = janet_checksize(janet_unmarshalval1);
	if((int)janet_checksizeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   JanetTable* janet_opttableval1 = janet_opttable(&janet_wrap_nilval1, JANET_MAX_MACRO_EXPAND, janet_checksizeval1, JANET_FRAME_SIZE);
	if(!janet_opttableval1){
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

        LLVMFuzzerTestOneInput_209(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    