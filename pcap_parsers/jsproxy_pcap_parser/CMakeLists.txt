cmake_minimum_required(VERSION 3.2)

set(PROJECT_NAME jsproxy_pcap_parser)
project(${PROJECT_NAME})

set(CMAKE_CXX_FLAGS "-std=c++17 -g -O2 -Wall -Wextra -Weffc++ -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations")

SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules")
find_package(Boost 1.66 COMPONENTS program_options system regex REQUIRED)
find_package(PCAP REQUIRED)

include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${PCAP_INCLUDE_DIRS})
include_directories(../../common/)

add_executable(${PROJECT_NAME}
                src/main.cpp
                src/session_parser.cpp
                ../../common/winbox_message.cpp
                ../../common/sha1.cpp
                ../../common/md4.cpp
                ../../common/rc4.cpp
                ../../common/des.cpp)

target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES} ${Boost_LIBRARIES})
