#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_302(char *fuzzData, size_t size)
{
	

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_gethalfrangeval1 = janet_gethalfrange(&janet_wrap_nilval1, JANET_FILE_NONIL, JANET_EV_TCTAG_ERR_STRINGF, fuzzData);
	if((int)janet_gethalfrangeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char* janet_optcstringval1 = janet_optcstring(NULL, janet_gethalfrangeval1, JANET_FILE_APPEND, &janet_symbol_genval1);
	if(!janet_optcstringval1){
		fprintf(stderr, "err");
		exit(0);	}
   JanetSymbol janet_csymbolval1 = janet_csymbol(janet_optcstringval1);
   JanetSymbol janet_optsymbolval1 = janet_optsymbol(&janet_wrap_nilval1, JANET_TFLAG_STRING, janet_initval2, janet_csymbolval1);
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

        LLVMFuzzerTestOneInput_302(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    