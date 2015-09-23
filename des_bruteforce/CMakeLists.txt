cmake_minimum_required(VERSION 2.8)

# Options
option(debug "Build with debug flags." ON)

set(PROJECT_NAME jsproxy_des_bruteforce)
project(${PROJECT_NAME})

# compiler flags
if (debug)
    set(CMAKE_CXX_FLAGS "-g -O2 -std=c++0x -Wall -Wextra -Weffc++ -Wshadow -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations")
else()
    set(CMAKE_CXX_FLAGS "-s -O2 -std=c++0x -Wall -Wextra -Wno-deprecated-declarations")
endif()

# package locations
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules")
find_package(Boost 1.46 COMPONENTS program_options system REQUIRED)
find_package(PCAP REQUIRED)

# includes
include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${PCAP_INCLUDE_DIRS})
include_directories("${PROJECT_SOURCE_DIR}/../common/")

# compilation units
add_executable(${PROJECT_NAME}
                src/main.cpp
                src/session_parser.cpp
                ${PROJECT_SOURCE_DIR}/../common/des.cpp
                ${PROJECT_SOURCE_DIR}/../common/sha1.cpp
                ${PROJECT_SOURCE_DIR}/../common/md4.cpp)

# linking comp / libs
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES} ${Boost_LIBRARIES})
