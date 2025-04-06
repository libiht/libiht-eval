cmake_minimum_required(VERSION 3.10)

project(drcftrace)
add_library(drcftrace SHARED
    drcftrace.c
    utils.c
)

find_package(DynamoRIO REQUIRED)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(drcftrace)
use_DynamoRIO_extension(drcftrace "drmgr")
use_DynamoRIO_extension(drcftrace "drx")