cmake_minimum_required(VERSION 3.2)

set(PROJECT_NAME winbox_pcap_decrypt)
project(${PROJECT_NAME})

set(CMAKE_CXX_FLAGS "-std=c++17 -g -O2 -Wall -Wextra -Weffc++ -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations")

SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules")
find_package(Boost COMPONENTS program_options system regex REQUIRED)
find_package(PCAP REQUIRED)

include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${PCAP_INCLUDE_DIRS})
include_directories(../../common/)

add_executable(${PROJECT_NAME}
                src/main.cpp
                ../../common/winbox_message.cpp
                ../../common/md5.cpp)

target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES} ${Boost_LIBRARIES})
