
cmake_minimum_required(VERSION 3.1)

project(sniffsd)

set(HEADERS_DIR, headers)
set(SOURCES_DIR, sources)
include_directories(${HEADERS_DIR})
include_directories(${SOURCES_DIR})

set(SOURCE_SNIFFSD ./sources/sniffsd.c)
set(SNIFFSD sniffd)

add_executable(${SNIFFSD} ${SOURCE_SNIFFSD})


set(SOURCE_INTFCD ./sources/intfcd.c)
set(INTFCD intfcd)

add_executable(${INTFCD} ${SOURCE_INTFCD})
