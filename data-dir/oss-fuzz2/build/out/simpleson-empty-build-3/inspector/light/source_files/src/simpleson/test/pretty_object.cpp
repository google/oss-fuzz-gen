#include "json.h"
#include "test.h"
#include <math.h>

int main(void)
{
	const char *input =
		"{\n"
		    "\t\"number\": 123.456,\n"
		    "\t\"string\": \"hello \\\" world\",\n"
		    "\t\"array\": [\n"
                "\t\t1,\n"
                "\t\t2,\n"
                "\t\t3\n"
            "\t],\n"
		    "\t\"boolean\": true,\n"
		    "\t\"isnull\": null,\n"
		    "\t\"objarray\": [\n"
                "\t\t{\n"
                    "\t\t\t\"key\": \"value\"\n"
                "\t\t}\n"
            "\t],\n"
		    "\t\"strarray\": [\n"
                "\t\t\"hello\",\n"
                "\t\t\"world\"\n"
            "\t],\n"
		    "\t\"emptyarray\": []\n"
		"}";

    printf("Input: \n%s\n", input);

	json::jobject result = json::jobject::parse(input);
	TEST_FALSE(result.is_array());
	TEST_STRING_EQUAL(result.get("number").c_str(), "123.456");
	TEST_STRING_EQUAL(result.get("string").c_str(), "\"hello \\\" world\"");
	TEST_STRING_EQUAL(result.get("array").c_str(), "[1,2,3]");
	TEST_STRING_EQUAL(result.get("boolean").c_str(), "true");
	TEST_STRING_EQUAL(result.get("isnull").c_str(), "null");
	TEST_STRING_EQUAL(result.get("objarray").c_str(), "[{\"key\":\"value\"}]");
	TEST_STRING_EQUAL(result.get("strarray").c_str(), "[\"hello\",\"world\"]");
	TEST_STRING_EQUAL(result.get("emptyarray").c_str(), "[]");
	TEST_TRUE(result.has_key("number"));
	TEST_FALSE(result.has_key("nokey"));
	TEST_STRING_EQUAL(result["objarray"].array(0).get("key").as_string().c_str(), "value");
	std::vector<std::string> strarray = result["strarray"];
	TEST_EQUAL(strarray.size(), 2);
	TEST_STRING_EQUAL(strarray[0].c_str(), "hello");
	TEST_STRING_EQUAL(strarray[1].c_str(), "world");
	std::vector<std::string> emptyarray = result["emptyarray"];
	TEST_EQUAL(emptyarray.size(), 0);

    printf("Output\n%s\n", result.pretty().c_str());

	// Test serialization
	TEST_STRING_EQUAL(result.pretty().c_str(), input);

	// Test copy constructor
	json::jobject copy(result);
	TEST_STRING_EQUAL(copy.as_string().c_str(), result.as_string().c_str());
}