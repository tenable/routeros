cmake_minimum_required(VERSION 3.2)

set(PROJECT_NAME message_tests)
project(${PROJECT_NAME})

set(CMAKE_CXX_FLAGS "-g -std=c++0x -Wall -Wextra -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations -Wshadow")

find_package(Boost REQUIRED)

include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(../common/)

# compilation units
add_executable(${PROJECT_NAME}
                src/winbox_parse_json_test.cpp
                src/winbox_parse_test.cpp
                src/winbox_parse_json_test.cpp
                src/winbox_serialize_json_test.cpp
                ../common/winbox_message.cpp)

# linking comp / libs
target_link_libraries(${PROJECT_NAME} -lgtest -lgtest_main -lpthread)
