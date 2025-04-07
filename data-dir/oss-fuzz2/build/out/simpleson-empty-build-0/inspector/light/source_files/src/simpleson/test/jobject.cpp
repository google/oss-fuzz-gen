#include "json.h"
#include "test.h"
#include <math.h>

int main(void)
{
	const char *input =
		"{"
		"	\"number\":123.456,"
		"	\"string\":\"hello \\\" world\","
		"	\"array\":[1,2,3],"
		"	\"boolean\":true,"
		"	\"isnull\":null,"
		"	\"objarray\":[{\"key\":\"value\"}],"
		"	\"strarray\":[\"hello\",\"world\"],"
		"	\"emptyarray\":[]"
		"}";

	json::jobject result = json::jobject::parse(input);

	// Test key list
	json::key_list_t keys = result.list_keys();
	TEST_EQUAL(keys.size(), 8);
	TEST_CONTAINS(keys, "number");
	TEST_CONTAINS(keys, "string");
	TEST_CONTAINS(keys, "array");
	TEST_CONTAINS(keys, "boolean");
	TEST_CONTAINS(keys, "isnull");
	TEST_CONTAINS(keys, "objarray");
	TEST_CONTAINS(keys, "strarray");
	TEST_CONTAINS(keys, "emptyarray");

	// Test individual entries
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

	// Assign some new values
	result.set("newvalue", "789");
	TEST_STRING_EQUAL(result.get("newvalue").c_str(), "789");
	result.set("array", "[4,5,6]");
	TEST_STRING_EQUAL(result.get("array").c_str(), "[4,5,6]");

	// Create a JSON object
	json::jobject test;
	test["int"] = 123;
	test["float"] = 12.3f;
	test["string"] = "test \"string";
	int test_array[3] = { 1, 2, 3 };
	test["array"] = std::vector<int>(test_array, test_array + 3);
	std::string test_string_array[2] = { "hello", "world" };
	test["strarray"] = std::vector<std::string>(test_string_array, test_string_array + 2);
	test["emptyarray"] = std::vector<std::string>();
	test["boolean"].set_boolean(true);
	test["null"].set_null();

	json::jobject subobj;
	char world[6] = "world";
	subobj["hello"] = world;
	test["subobj"] = subobj;

	std::vector<json::jobject> objarray;
	objarray.push_back(subobj);
	objarray.push_back(subobj);
	test["objarray"] = objarray;

	std::string serial = (std::string)test;
	json::jobject retest = json::jobject::parse(serial.c_str());

	// Integer
	TEST_EQUAL((int)retest["int"], 123);
	TEST_FALSE(retest["int"].is_string());
	TEST_TRUE(retest["int"].is_number());
	TEST_FALSE(retest["int"].is_object());
	TEST_FALSE(retest["int"].is_array());
	TEST_FALSE(retest["int"].is_bool());
	TEST_FALSE(retest["int"].is_null());

	// Float
	TEST_TRUE(fabs((float)retest["float"] - 12.3f) < 1.0e-6);
	TEST_FALSE(retest["float"].is_string());
	TEST_TRUE(retest["float"].is_number());
	TEST_FALSE(retest["float"].is_object());
	TEST_FALSE(retest["float"].is_array());
	TEST_FALSE(retest["float"].is_bool());
	TEST_FALSE(retest["float"].is_null());

	// String
	TEST_STRING_EQUAL(retest["string"].as_string().c_str(), "test \"string");
	TEST_TRUE(retest["string"].is_string());
	TEST_FALSE(retest["string"].is_number());
	TEST_FALSE(retest["string"].is_object());
	TEST_FALSE(retest["string"].is_array());
	TEST_FALSE(retest["string"].is_bool());
	TEST_FALSE(retest["string"].is_null());

	// Array
	std::vector<int> retest_array = retest["array"];
	TEST_TRUE(retest_array == std::vector<int>(test_array, test_array + 3));
	TEST_FALSE(retest["array"].is_string());
	TEST_FALSE(retest["array"].is_number());
	TEST_TRUE(retest["array"].is_object());
	TEST_TRUE(retest["array"].is_array());
	TEST_FALSE(retest["array"].is_bool());
	TEST_FALSE(retest["array"].is_null());

	// Object
	json::jobject resubobj = retest["subobj"];
	TEST_STRING_EQUAL(resubobj["hello"].as_string().c_str(), "world");
	TEST_FALSE(retest["subobj"].is_string());
	TEST_FALSE(retest["subobj"].is_number());
	TEST_TRUE(retest["subobj"].is_object());
	TEST_FALSE(retest["subobj"].is_array());
	TEST_FALSE(retest["subobj"].is_bool());
	TEST_FALSE(retest["subobj"].is_null());

	// Object array
	TEST_TRUE(retest["objarray"].array(0).as_object() == subobj);
	strarray = retest["strarray"];
	TEST_EQUAL(strarray.size(), 2);
	TEST_STRING_EQUAL(strarray[0].c_str(), "hello");
	TEST_STRING_EQUAL(strarray[1].c_str(), "world");
	std::vector<json::jobject> objarrayecho = test["objarray"];
	TEST_EQUAL(objarrayecho.size(), 2);
	TEST_FALSE(retest["objarray"].is_string());
	TEST_FALSE(retest["objarray"].is_number());
	TEST_TRUE(retest["objarray"].is_object());
	TEST_TRUE(retest["objarray"].is_array());
	TEST_FALSE(retest["objarray"].is_bool());
	TEST_FALSE(retest["objarray"].is_null());

	// Empty array
	emptyarray = retest["emptyarray"];
	TEST_EQUAL(emptyarray.size(), 0);
	TEST_FALSE(retest["emptyarray"].is_string());
	TEST_FALSE(retest["emptyarray"].is_number());
	TEST_TRUE(retest["emptyarray"].is_object());
	TEST_TRUE(retest["emptyarray"].is_array());
	TEST_FALSE(retest["emptyarray"].is_bool());
	TEST_FALSE(retest["emptyarray"].is_null());

	// Boolean
	TEST_TRUE(retest.has_key("boolean"));
	TEST_FALSE(retest["boolean"].is_string());
	TEST_FALSE(retest["boolean"].is_number());
	TEST_FALSE(retest["boolean"].is_object());
	TEST_FALSE(retest["boolean"].is_array());
	TEST_TRUE(retest["boolean"].is_bool());
	TEST_FALSE(retest["boolean"].is_null());
	TEST_TRUE(test["boolean"].is_true());

	// Null
	TEST_TRUE(test.has_key("null"));
	TEST_FALSE(retest["null"].is_string());
	TEST_FALSE(retest["null"].is_number());
	TEST_FALSE(retest["null"].is_object());
	TEST_FALSE(retest["null"].is_array());
	TEST_FALSE(retest["null"].is_bool());
	TEST_TRUE(retest["null"].is_null());

	// Test copy constructor
	json::jobject copy(test);
	TEST_STRING_EQUAL(copy.as_string().c_str(), test.as_string().c_str());
}