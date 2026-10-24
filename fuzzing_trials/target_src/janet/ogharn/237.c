#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_237(char *fuzzData, size_t size)
{
	

   JanetKV janet_sorted_keysvar0;
	memset(&janet_sorted_keysvar0, 0, sizeof(janet_sorted_keysvar0));

   JanetBuffer janet_marshalvar0;
	memset(&janet_marshalvar0, 0, sizeof(janet_marshalvar0));

   Janet janet_marshalvar1;
	memset(&janet_marshalvar1, 0, sizeof(janet_marshalvar1));

   JanetTable janet_marshalvar2;
	memset(&janet_marshalvar2, 0, sizeof(janet_marshalvar2));

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_getargindexval1 = janet_getargindex(&janet_wrap_nilval1, JANET_TFLAG_INDEXED, janet_initval1, fuzzData);
	if((int)janet_getargindexval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t janet_sorted_keysval1 = janet_sorted_keys(&janet_sorted_keysvar0, JANET_EV_TCTAG_ERR_KEYWORD, &janet_getargindexval1);
	if((int)janet_sorted_keysval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   janet_marshal(&janet_marshalvar0, janet_marshalvar1, &janet_marshalvar2, janet_sorted_keysval1);
   janet_table_merge_table(&janet_marshalvar2, &janet_marshalvar2);
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

        LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    