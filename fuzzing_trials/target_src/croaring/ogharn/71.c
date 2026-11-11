#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_71(char *fuzzData, size_t size)
{
	

   uint64_t roaring64_bitmap_add_checkedvar1;
	memset(&roaring64_bitmap_add_checkedvar1, 0, sizeof(roaring64_bitmap_add_checkedvar1));

   array_container_t array_container_growvar0;
	memset(&array_container_growvar0, 0, sizeof(array_container_growvar0));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool roaring64_bitmap_add_checkedval1 = roaring64_bitmap_add_checked(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_add_checkedvar1);
   array_container_grow(&array_container_growvar0, CROARING_CLANG_VISUAL_STUDIO, roaring64_bitmap_add_checkedval1);
   array_container_add_range_nvals(&array_container_growvar0, 0, 1, 64, 0);
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

        LLVMFuzzerTestOneInput_71(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    