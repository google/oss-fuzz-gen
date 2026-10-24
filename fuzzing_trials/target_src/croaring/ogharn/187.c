#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_187(char *fuzzData, size_t size)
{
	

   char* roaring64_bitmap_portable_serializevar1[size+1];
	sprintf(roaring64_bitmap_portable_serializevar1, "/tmp/sw06c");
   uint16_t intersect_uint16var0;
	memset(&intersect_uint16var0, 0, sizeof(intersect_uint16var0));

   uint16_t intersect_uint16var2;
	memset(&intersect_uint16var2, 0, sizeof(intersect_uint16var2));

   uint16_t intersect_uint16var4;
	memset(&intersect_uint16var4, 0, sizeof(intersect_uint16var4));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_serializeval1 = roaring64_bitmap_portable_serialize(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_serializevar1);
	if((int)roaring64_bitmap_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t intersect_uint16val1 = intersect_uint16(&intersect_uint16var0, roaring64_bitmap_portable_serializeval1, &intersect_uint16var2, roaring64_bitmap_portable_serializeval1, &intersect_uint16var4);
	if((int)intersect_uint16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   array_container_t* array_container_create_rangeval1 = array_container_create_range(CROARING_ATOMIC_IMPL_CPP, intersect_uint16val1);
	if(!array_container_create_rangeval1){
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

        LLVMFuzzerTestOneInput_187(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    