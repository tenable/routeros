cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME jsproxy_pcap_password_bruteforce)
project(${PROJECT_NAME})

# compiler flags
set(CMAKE_CXX_FLAGS "-std=c++17 -g -O2 -Wall -Wextra -Weffc++ -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations")

# package locations
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules")
find_package(Boost COMPONENTS program_options system REQUIRED)
find_package(PCAP REQUIRED)

# includes
include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${PCAP_INCLUDE_DIRS})
include_directories(../../common/)

# compilation units
add_executable(${PROJECT_NAME}
                src/main.cpp
                src/session_parser.cpp
                ../../common/des.cpp
                ../../common/sha1.cpp
                ../../common/md4.cpp)

# linking comp / libs
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES} ${Boost_LIBRARIES})
