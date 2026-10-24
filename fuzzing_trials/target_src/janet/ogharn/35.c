#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_35(char *fuzzData, size_t size)
{
	

   JanetTable janet_env_lookup_intovar1;
	memset(&janet_env_lookup_intovar1, 0, sizeof(janet_env_lookup_intovar1));

   char* janet_env_lookup_intovar2[size+1];
	sprintf(janet_env_lookup_intovar2, "/tmp/tl60f");
   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_gethalfrangeval1 = janet_gethalfrange(&janet_wrap_nilval1, JANET_FILE_NONIL, JANET_EV_TCTAG_ERR_STRINGF, fuzzData);
	if((int)janet_gethalfrangeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   janet_env_lookup_into(NULL, &janet_env_lookup_intovar1, janet_env_lookup_intovar2, janet_gethalfrangeval1);
   JanetTable* janet_core_lookup_tableval1 = janet_core_lookup_table(&janet_env_lookup_intovar1);
	if(!janet_core_lookup_tableval1){
		fprintf(stderr, "err");
		exit(0);	}
   JanetTable* janet_env_lookupval1 = janet_env_lookup(janet_core_lookup_tableval1);
	if(!janet_env_lookupval1){
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

        LLVMFuzzerTestOneInput_35(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    