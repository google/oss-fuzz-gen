#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
{
	

   JanetKV janet_sorted_keysvar0;
	memset(&janet_sorted_keysvar0, 0, sizeof(janet_sorted_keysvar0));

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
   Janet janet_asm_decode_instructionval1 = janet_asm_decode_instruction(janet_getargindexval1);
   JanetCompileResult janet_compileval1 = janet_compile(janet_asm_decode_instructionval1, NULL, NULL);
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

        LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    