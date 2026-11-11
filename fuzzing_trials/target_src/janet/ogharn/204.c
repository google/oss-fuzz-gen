#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_204(char *fuzzData, size_t size)
{
	

   void* janet_pointer_buffer_unsafevar0[size+1];
	sprintf(janet_pointer_buffer_unsafevar0, "/tmp/vu86d");
   int32_t janet_pointer_buffer_unsafevar2;
	memset(&janet_pointer_buffer_unsafevar2, 0, sizeof(janet_pointer_buffer_unsafevar2));

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_gethalfrangeval1 = janet_gethalfrange(&janet_wrap_nilval1, JANET_FILE_NONIL, JANET_EV_TCTAG_ERR_STRINGF, fuzzData);
	if((int)janet_gethalfrangeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   JanetBuffer* janet_pointer_buffer_unsafeval1 = janet_pointer_buffer_unsafe(janet_pointer_buffer_unsafevar0, janet_gethalfrangeval1, janet_pointer_buffer_unsafevar2);
	if(!janet_pointer_buffer_unsafeval1){
		fprintf(stderr, "err");
		exit(0);	}
   janet_buffer_push_bytes(janet_pointer_buffer_unsafeval1, fuzzData, JANET_STACKFRAME_TAILCALL);
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

        LLVMFuzzerTestOneInput_204(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    