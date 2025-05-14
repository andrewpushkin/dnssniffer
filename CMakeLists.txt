cmake_minimum_required(VERSION 3.10)
project(dnssniffer C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Add include directories
include_directories(${PCAP_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add source files
set(SOURCES
    src/main.c
    src/dns_parser.c
    src/packet_capture.c
)

# Create executable
add_executable(dnssniffer ${SOURCES})

# Link libraries
target_link_libraries(dnssniffer ${PCAP_LIBRARIES})

# Add compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dnssniffer PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Use system GoogleTest if available
find_package(GTest REQUIRED)

enable_testing()
add_executable(test_dns_parser tests/test_dns_parser.cpp src/dns_parser.c)
set_target_properties(test_dns_parser PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_dns_parser GTest::gtest_main)
target_include_directories(test_dns_parser PRIVATE include)
add_test(NAME test_dns_parser COMMAND test_dns_parser)