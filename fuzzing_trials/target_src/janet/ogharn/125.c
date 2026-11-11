#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_125(char *fuzzData, size_t size)
{
	

   JanetBuffer janet_prettyvar0;
	memset(&janet_prettyvar0, 0, sizeof(janet_prettyvar0));

   Janet janet_prettyvar3;
	memset(&janet_prettyvar3, 0, sizeof(janet_prettyvar3));

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_getargindexval1 = janet_getargindex(&janet_wrap_nilval1, JANET_TFLAG_INDEXED, janet_initval1, fuzzData);
	if((int)janet_getargindexval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   JanetBuffer* janet_prettyval1 = janet_pretty(&janet_prettyvar0, janet_getargindexval1, janet_initval1, janet_prettyvar3);
	if(!janet_prettyval1){
		fprintf(stderr, "err");
		exit(0);	}
   janet_buffer_push_string(janet_prettyval1, janet_symbol_genval1);
   int janet_string_compareval1 = janet_string_compare(janet_symbol_genval1, janet_symbol_genval1);
	if((int)janet_string_compareval1 < 0){
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

        LLVMFuzzerTestOneInput_125(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    