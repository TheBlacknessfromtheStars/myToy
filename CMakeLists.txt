cmake_minimum_required(VERSION 3.26)
project(ace VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
file(GLOB SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.c)

add_executable(ace ${SRC_FILES})
target_include_directories(ace
        PUBLIC ${PROJECT_SOURCE_DIR}/include)
