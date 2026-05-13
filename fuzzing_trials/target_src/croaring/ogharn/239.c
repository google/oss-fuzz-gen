#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_239(char *fuzzData, size_t size)
{
	

   char* roaring64_bitmap_portable_serializevar1[size+1];
	sprintf(roaring64_bitmap_portable_serializevar1, "/tmp/p96jq");
   void* array_container_to_uint32_array_vector16var0[size+1];
	sprintf(array_container_to_uint32_array_vector16var0, "/tmp/r7vib");
   uint16_t array_container_to_uint32_array_vector16var1;
	memset(&array_container_to_uint32_array_vector16var1, 0, sizeof(array_container_to_uint32_array_vector16var1));

   uint16_t difference_uint16var2;
	memset(&difference_uint16var2, 0, sizeof(difference_uint16var2));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_serializeval1 = roaring64_bitmap_portable_serialize(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_serializevar1);
	if((int)roaring64_bitmap_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int array_container_to_uint32_array_vector16val1 = array_container_to_uint32_array_vector16(array_container_to_uint32_array_vector16var0, &array_container_to_uint32_array_vector16var1, roaring64_bitmap_portable_serializeval1, BITSET_CONTAINER_TYPE);
	if((int)array_container_to_uint32_array_vector16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int difference_uint16val1 = difference_uint16(&array_container_to_uint32_array_vector16var1, SHARED_CONTAINER_TYPE, &difference_uint16var2, array_container_to_uint32_array_vector16val1, &array_container_to_uint32_array_vector16var1);
	if((int)difference_uint16val1 < 0){
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

        LLVMFuzzerTestOneInput_239(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    