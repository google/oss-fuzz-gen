#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arraylist.h>
#include <json_object.h>
#include <json_object_iterator.h>
#include <json_tokener.h>
#include <json_util.h>
#include <linkhash.h>

extern "C" int LLVMFuzzerTestOneInput_21(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/vgcxg");
   char* json_object_object_get_exvar1[size+1];
	sprintf((char *)json_object_object_get_exvar1, "/tmp/0uhgr");
   double json_object_set_doublevar1 = 2.0;
   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_tokener_parseval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_object_get_exval1 = json_object_object_get_ex(NULL, (const char *)json_object_object_get_exvar1, &json_tokener_parseval1);
	if((int)json_object_object_get_exval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_set_doubleval1 = json_object_set_double(json_tokener_parseval1, json_object_set_doublevar1);
	if((int)json_object_set_doubleval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
