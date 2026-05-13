#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_16(char *fuzzData, size_t size)
{
	
        
   icalcomponent_kind ICAL_VEVENT_COMPONENTVAL = ICAL_VEVENT_COMPONENT;

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   icalcompiter icalcomponent_end_componentval1 = icalcomponent_end_component(icalcomponent_new_from_stringval1, ICAL_VEVENT_COMPONENTVAL);
   return 0;
}
