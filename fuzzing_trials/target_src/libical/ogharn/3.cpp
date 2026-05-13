#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   int icalcomponent_check_restrictionsval1 = icalcomponent_check_restrictions(icalcomponent_new_from_stringval1);
	if(icalcomponent_check_restrictionsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_convert_errors(icalcomponent_new_from_stringval1);
   return 0;
}
