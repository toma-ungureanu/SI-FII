cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
project(Exercitiu1)

find_package(OpenSSL REQUIRED)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake) # main (top) cmake dir
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) # project specific cmake dir
set(APP_SOURCES exercitiul2.cpp)
set(APPLICATION_NAME exercitiul2)
set(PLAIN_TEXT_FILE1    "../text/file1.txt")
set(PLAIN_TEXT_FILE2    "../text/file2.txt")
set(HASH1_SHA256_FILE   "../text/hash1_sha256.txt")
set(HASH2_SHA256_FILE   "../text/hash2_sha256.txt")
set(HASH1_MD5_FILE      "../text/hash1_md5.txt")
set(HASH2_MD5_FILE      "../text/hash2_md5.txt")

add_executable(${APPLICATION_NAME} ${APP_SOURCES})

target_link_libraries(${APPLICATION_NAME} ${LIBRARY_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(${APPLICATION_NAME}
        PRIVATE
        -DPLAIN_TEXT_FILE1="${PLAIN_TEXT_FILE1}"
        -DPLAIN_TEXT_FILE2="${PLAIN_TEXT_FILE2}"
        -DHASH1_SHA256_FILE="${HASH1_SHA256_FILE}"
        -DHASH2_SHA256_FILE="${HASH2_SHA256_FILE}"
        -DHASH1_MD5_FILE="${HASH1_MD5_FILE}"
        -DHASH2_MD5_FILE="${HASH2_MD5_FILE}"
        )