cmake_minimum_required(VERSION 3.14)
project(IcmpTunnel CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_library(tunnel src/icmp_tunnel.cpp)

add_executable(icmp_client src/client_main.cpp)
target_link_libraries(icmp_client tunnel)

add_executable(icmp_server src/server_main.cpp)
target_link_libraries(icmp_server tunnel)
