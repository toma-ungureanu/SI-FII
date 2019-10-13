cmake_minimum_required(VERSION 3.15)
project(SITema1)
set(CMAKE_CXX_STANDARD 17)

add_executable(SITema1 main.cpp)
find_package(OpenSSL REQUIRED)
target_link_libraries(SITema1 OpenSSL::SSL OpenSSL::Crypto)
