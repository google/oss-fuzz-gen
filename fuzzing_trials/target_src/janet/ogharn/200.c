#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <janet.h>

static void function_pointer3458764518831685632fp(JanetFiber*, JanetAsyncEvent){
	exit(0);
}
int LLVMFuzzerTestOneInput_200(char *fuzzData, size_t size)
{
	

   void* janet_optpointervar3[size+1];
	sprintf(janet_optpointervar3, "/tmp/ugw6t");
   JanetFiber janet_async_start_fibervar0;
	memset(&janet_async_start_fibervar0, 0, sizeof(janet_async_start_fibervar0));

   JanetStream janet_async_start_fibervar1;
	memset(&janet_async_start_fibervar1, 0, sizeof(janet_async_start_fibervar1));

   JanetAsyncMode janet_async_start_fibervar2;
	memset(&janet_async_start_fibervar2, 0, sizeof(janet_async_start_fibervar2));

   int janet_initval1 = janet_init();
   int janet_initval2 = janet_init();
   JanetSymbol janet_symbol_genval1 = janet_symbol_gen();
   Janet janet_wrap_nilval1 = janet_wrap_nil();
   int32_t janet_gethalfrangeval1 = janet_gethalfrange(&janet_wrap_nilval1, JANET_FILE_NONIL, JANET_EV_TCTAG_ERR_STRINGF, fuzzData);
	if((int)janet_gethalfrangeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   void* janet_optpointerval1 = janet_optpointer(&janet_wrap_nilval1, janet_gethalfrangeval1, JANET_STREAM_NOT_CLOSEABLE, janet_optpointervar3);
	if(!janet_optpointerval1){
		fprintf(stderr, "err");
		exit(0);	}
   janet_async_start_fiber(&janet_async_start_fibervar0, &janet_async_start_fibervar1, janet_async_start_fibervar2, function_pointer3458764518831685632fp, (void*)janet_optpointerval1);
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

        LLVMFuzzerTestOneInput_200(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    