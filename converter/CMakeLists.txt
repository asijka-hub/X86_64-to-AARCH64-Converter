cmake_minimum_required(VERSION 3.25)
project(converter)

set(CMAKE_CXX_STANDARD 20)

add_executable(converter src/converter.cpp)

include(FindPkgConfig)

pkg_check_modules (CAPSTONE REQUIRED capstone)

# Use CAPSTONE_FOUND, CAPSTONE_LIBRARIES, CAPSTONE_INCLUDE_DIRS vars
target_link_libraries(converter ${CAPSTONE_LIBRARIES})

target_include_directories(converter PUBLIC "/usr/include/capstone")