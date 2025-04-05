cmake_minimum_required(VERSION 3.10)

project(drcfg)
add_library(drcfg SHARED
    drcfg.c
    utils.c
)

find_package(DynamoRIO REQUIRED)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(drcfg)
use_DynamoRIO_extension(drcfg "drmgr")
use_DynamoRIO_extension(drcfg "drx")