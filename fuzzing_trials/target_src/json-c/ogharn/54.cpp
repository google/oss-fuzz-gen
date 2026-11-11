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
extern "C" int LLVMFuzzerTestOneInput_54(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/0ao3q");
   void* json_object_set_userdatavar1[size+1];
	sprintf((char *)json_object_set_userdatavar1, "/tmp/ibh43");
   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_tokener_parseval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   json_object_set_userdata(json_tokener_parseval1, json_object_set_userdatavar1, function_pointer3458764515962781696fp);
   json_object_set_serializer(json_tokener_parseval1, NULL, NULL, NULL);
   return 0;
}
