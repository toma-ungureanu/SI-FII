cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
project(Exercitiu1)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake) # main (top) cmake dir
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) # project specific cmake dir
set(APP_SOURCES exercitiul3.cpp)
set(APPLICATION_NAME exercitiul3)
add_executable(${APPLICATION_NAME} ${APP_SOURCES})
find_package(OpenSSL REQUIRED)
target_link_libraries(${APPLICATION_NAME} ${LIBRARY_NAME} OpenSSL::SSL OpenSSL::Crypto)
