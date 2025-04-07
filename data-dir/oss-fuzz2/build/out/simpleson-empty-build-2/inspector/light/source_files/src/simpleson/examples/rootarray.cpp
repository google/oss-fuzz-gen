#include "json.h"
#include <stdio.h>
#include <assert.h>

int main(void)
{
	// Create a couple objects
    const std::string test = 
    "["
    "   {"
    "       \"firstName\": \"Jimmy\","
    "       \"lastName\": \"D\","
    "       \"hobbies\": ["
    "           {"
    "               \"sport\": \"tennis\""
    "           },"
    "           {"
    "               \"music\": \"rock\""
    "           }"
    "       ]"
    "   },"
    "   {"
    "       \"firstName\": \"Sussi\","
    "       \"lastName\": \"Q\","
    "       \"hobbies\": ["
    "           {"
    "               \"sport\": \"volleyball\""
    "           },"
    "           {"
    "               \"music\": \"classical\""
    "           }"
    "       ]"
    "   }"
    "]";

    // Parse the test array
    json::jobject example = json::jobject::parse(test);

    // Access the data
    std::string music_desired = example.array(0).get("hobbies").array(1).get("music").as_string();

    // Print the data
    printf("Music desired: %s\n", music_desired.c_str()); // Returns "rock"

    // Check the result
    assert(music_desired == std::string("rock"));

    // Access the second entry
    music_desired = example.array(1).get("hobbies").array(1).get("music").as_string();

    // Print the data
    printf("Music desired: %s\n", music_desired.c_str()); // Returns "classical"

    // Check the result
    assert(music_desired == std::string("classical"));
}