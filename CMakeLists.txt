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

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_executable(tests tests/tests.cpp)
target_link_libraries(tests tunnel gtest_main)

include(GoogleTest)
gtest_discover_tests(tests)
