#include "json.h"
#include "test.h"

const char *test_data =
"{"
"	\"_id\": \"5b8ae80aa0ad7bab287b087c\","
"	\"index\" : 0,"
"	\"guid\" : \"d05c39f8-e92d-4911-b727-fe3d78b6de6c\","
"	\"isActive\" : true,"
"	\"balance\" : \"$3,801.20\","
"	\"picture\" : \"http://placehold.it/32x32\","
"	\"age\" : 38,"
"	\"eyeColor\" : \"blue\","
"	\"name\" : \"Garrett Beck\","
"	\"gender\" : \"male\","
"	\"company\" : \"PERMADYNE\","
"	\"email\" : \"garrettbeck@permadyne.com\","
"	\"phone\" : \"+1 (813) 532-3550\","
"	\"address\" : \"191 Crawford Avenue, Echo, Oklahoma, 6993\","
"	\"about\" : \"Deserunt deserunt quis laboris elit aliquip labore veniam mollit consequat esse labore. Nulla et tempor labore quis et magna do. Do officia sit aute ullamco in reprehenderit irure. Officia laborum amet ad ea labore fugiat excepteur proident aute.\r\n\","
"	\"registered\" : \"2015-11-19T08:36:06 -01:00\","
"	\"latitude\" : 41.271876,"
"	\"longitude\" : 15.372805,"
"	\"tags\" : ["
"		\"dolore\","
"			\"adipisicing\","
"			\"nostrud\","
"			\"elit\","
"			\"est\","
"			\"et\","
"			\"sunt\""
"	],"
"	\"friends\": ["
"		{"
"			\"id\": 0,"
"				\"name\" : \"Amie Jarvis\""
"		},"
"	{"
"		\"id\": 1,"
"		\"name\" : \"Rosanna Gonzales\""
"	},"
"	{"
"		\"id\": 2,"
"		\"name\" : \"Rhodes Crane\""
"	}"
"	],"
"			\"greeting\": \"Hello, Garrett Beck! You have 7 unread messages.\","
"				\"favoriteFruit\" : \"strawberry\""
"}";

int main(void)
{
	json::jobject test_parse = json::jobject::parse(test_data);
	TEST_EQUAL(test_parse.size(), 22);
	const std::string echo_str = test_parse.as_string();
	json::jobject echo = json::jobject::parse(echo_str);
	TEST_EQUAL(echo.size(), 22);
}