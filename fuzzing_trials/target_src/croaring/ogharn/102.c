#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_102(char *fuzzData, size_t size)
{
	

   roaring_array_t ra_portable_deserializeoverload1var0;
	memset(&ra_portable_deserializeoverload1var0, 0, sizeof(ra_portable_deserializeoverload1var0));

   size_t ra_portable_deserializeoverload1var3 = 1;
   array_container_t array_container_readvar1;
	memset(&array_container_readvar1, 0, sizeof(array_container_readvar1));

   uint32_t array_container_rank_manyvar2;
	memset(&array_container_rank_manyvar2, 0, sizeof(array_container_rank_manyvar2));

   uint32_t array_container_rank_manyvar3;
	memset(&array_container_rank_manyvar3, 0, sizeof(array_container_rank_manyvar3));

   uint64_t array_container_rank_manyvar4;
	memset(&array_container_rank_manyvar4, 0, sizeof(array_container_rank_manyvar4));

   bool ra_portable_deserializeoverload1val1 = ra_portable_deserialize(&ra_portable_deserializeoverload1var0, fuzzData, size, &ra_portable_deserializeoverload1var3);
   size_t ra_portable_serializeval1 = ra_portable_serialize(&ra_portable_deserializeoverload1var0, fuzzData);
	if((int)ra_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t array_container_readval1 = array_container_read(ROARING_FLAG_COW, &array_container_readvar1, fuzzData);
	if((int)array_container_readval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint32_t array_container_rank_manyval1 = array_container_rank_many(&array_container_readvar1, ra_portable_serializeval1, &array_container_rank_manyvar2, &array_container_rank_manyvar3, &array_container_rank_manyvar4);
	if((int)array_container_rank_manyval1 < 0){
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

        LLVMFuzzerTestOneInput_102(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    