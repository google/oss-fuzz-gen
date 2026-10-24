#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_61(char *fuzzData, size_t size)
{
	
        

   struct icaltimetype icalcomponent_set_dtstartvar0;
	memset(&icalcomponent_set_dtstartvar0, 0, (sizeof icalcomponent_set_dtstartvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_set_dtstart(icalcomponent_new_from_stringval1, icalcomponent_set_dtstartvar0);
   struct icaltimetype icalcomponent_get_dtendval1 = icalcomponent_get_dtend(icalcomponent_new_from_stringval1);
   return 0;
}
