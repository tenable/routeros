cmake_minimum_required(VERSION 3.2)

option(test "Build all tests." OFF)

set(PROJECT_NAME get_policies)
project(${PROJECT_NAME})

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -Weffc++ -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations -Wshadow")

find_package(Boost 1.58 COMPONENTS program_options system regex REQUIRED)

include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(../common/)

add_executable(${PROJECT_NAME}
    src/main.cpp
    ../common/md5.cpp
    ../common/winbox_session.cpp
    ../common/winbox_message.cpp)

target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} -lpthread)
