#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
{
	

   struct cbor_load_result cbor_loadvar2;
	memset(&cbor_loadvar2, 0, sizeof(cbor_loadvar2));

   size_t cbor_serialize_arrayvar2 = 1;
   cbor_item_t* cbor_loadval1 = cbor_load((cbor_data)fuzzData, size, &cbor_loadvar2);
	if(!cbor_loadval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_serialize_arrayval1 = cbor_serialize_array(cbor_loadval1, (cbor_mutable_data) fuzzData, cbor_serialize_arrayvar2);
	if((int)cbor_serialize_arrayval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_serialize_bytestringval1 = cbor_serialize_bytestring(cbor_loadval1, (cbor_mutable_data)fuzzData, cbor_serialize_arrayval1);
	if((int)cbor_serialize_bytestringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_encode_indef_bytestring_startval1 = cbor_encode_indef_bytestring_start((unsigned char *)&fuzzData, size);
	if((int)cbor_encode_indef_bytestring_startval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
