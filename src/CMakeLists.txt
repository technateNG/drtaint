cmake_minimum_required(VERSION 3.15)
set(DynamoRIO_DIR "C:/Users/IEUser/Downloads/DynamoRIO-Windows-7.91.18192-0/cmake")

find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required.")
endif()

add_library(taint_engine SHARED "lib/engine.c")

add_library(drtaint SHARED drtaint.c)
target_include_directories(drtaint PUBLIC "lib")
target_link_libraries(drtaint taint_engine)

configure_DynamoRIO_client(drtaint)
use_DynamoRIO_extension(drtaint drmgr)
use_DynamoRIO_extension(drtaint drreg)
use_DynamoRIO_extension(drtaint drx)
use_DynamoRIO_extension(drtaint drutil)