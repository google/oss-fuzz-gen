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

static void function_pointer3458764515962781696fp(json_object*, void*){
	exit(0);
}
extern "C" int LLVMFuzzerTestOneInput_56(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/xxsvu");
   void* json_object_set_userdatavar1[size+1];
	sprintf((char *)json_object_set_userdatavar1, "/tmp/ujv54");
   struct printbuf json_object_userdata_to_json_stringvar1;
	memset(&json_object_userdata_to_json_stringvar1, 0, sizeof(json_object_userdata_to_json_stringvar1));

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_tokener_parseval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   json_object_set_userdata(json_tokener_parseval1, json_object_set_userdatavar1, function_pointer3458764515962781696fp);
   int json_object_userdata_to_json_stringval1 = json_object_userdata_to_json_string(json_tokener_parseval1, &json_object_userdata_to_json_stringvar1, JSON_C_STR_HASH_PERLLIKE, JSON_C_TO_STRING_PRETTY_TAB);
	if((int)json_object_userdata_to_json_stringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
