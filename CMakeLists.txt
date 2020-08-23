cmake_minimum_required(VERSION 3.17)
project(1m-block)

set(CMAKE_CXX_STANDARD 17)

add_executable(1m-block main.cpp)
target_link_libraries(1m-block -lpcap)
target_link_libraries(1m-block -lnetfilter_queue)