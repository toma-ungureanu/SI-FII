cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
project(Exercitiu1)

find_package(OpenSSL REQUIRED)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake) # main (top) cmake dir
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) # project specific cmake dir
set(APP_SOURCES exercitiul1.cpp)
set(APPLICATION_NAME exercitiul1)
set(PLAIN_TEXT_FILE "../text/plainText.txt")
set(CRYPTO_TEXT_FILE "../text/cryptoText.txt")
set(WORDS_TEXT_FILE "../text/words.txt")
set(MAX_PASSWORD_SIZE 15)

add_executable(${APPLICATION_NAME} ${APP_SOURCES})

target_link_libraries(${APPLICATION_NAME}  OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(${APPLICATION_NAME}
        PRIVATE
            -DPLAIN_TEXT_FILE="${PLAIN_TEXT_FILE}"
            -DCRYPTO_TEXT_FILE="${CRYPTO_TEXT_FILE}"
            -DWORDS_TEXT_FILE="${WORDS_TEXT_FILE}"
            -DMAX_PASSWORD_SIZE=${MAX_PASSWORD_SIZE}
        )