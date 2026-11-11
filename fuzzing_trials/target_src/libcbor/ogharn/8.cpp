#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_8(char *fuzzData, size_t size)
{
	

   struct cbor_load_result cbor_loadvar2;
	memset(&cbor_loadvar2, 0, sizeof(cbor_loadvar2));

   unsigned char** cbor_serialize_allocvar1[size+1];
	sprintf((char *)cbor_serialize_allocvar1, "/tmp/mavaq");
   size_t cbor_serialize_allocvarsize_tsize = sizeof(cbor_serialize_allocvar1);
   float cbor_encode_halfvar0 = 2.0;
   cbor_item_t* cbor_loadval1 = cbor_load((cbor_data)fuzzData, size, &cbor_loadvar2);
	if(!cbor_loadval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_serialize_allocval1 = cbor_serialize_alloc(cbor_loadval1, (unsigned char **)cbor_serialize_allocvar1, &cbor_serialize_allocvarsize_tsize);
	if((int)cbor_serialize_allocval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_encode_halfval1 = cbor_encode_half(cbor_encode_halfvar0, (unsigned char *)&fuzzData, cbor_serialize_allocvarsize_tsize);
	if((int)cbor_encode_halfval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   bool cbor_array_setval1 = cbor_array_set(cbor_loadval1, cbor_encode_halfval1, cbor_loadval1);
   return 0;
}
