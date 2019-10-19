cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
project(Exercitiu1)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake) # main (top) cmake dir
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) # project specific cmake dir
set(APP_SOURCES src/Main.cpp)
set(APPLICATION_NAME exercitiul3)
set(KEY_LENGTH 256)
set(INIT_VEC_LENGTH 16)
set(MESSAGE_FILE "../text/message.txt")

include_directories(include)
set(APP_SOURCES
        src/Main.cpp
        src/CtrKey.cpp src/CbcKey.cpp
        src/EcbKey.cpp
        src/KeyManager.cpp
        src/CommNode.cpp
        )
add_executable(${APPLICATION_NAME} ${APP_SOURCES})
find_package(OpenSSL REQUIRED)
target_link_libraries(${APPLICATION_NAME} ${LIBRARY_NAME} OpenSSL::SSL OpenSSL::Crypto)

target_compile_definitions(${APPLICATION_NAME}
        PRIVATE
        -DKEY_LENGTH=${KEY_LENGTH}
        -DINIT_VEC_LENGTH=${INIT_VEC_LENGTH}
        -DMESSAGE_FILE="${MESSAGE_FILE}"
        )

