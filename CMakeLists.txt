
cmake_minimum_required(VERSION 3.1)

project(sniffsd)

set(HEADERS_DIR, headers)
set(SOURCES_DIR, sources)
include_directories(${HEADERS_DIR})
include_directories(${SOURCES_DIR})

set(SOURCE_SNIFFSD ./sources/sniffsd.c ./sources/container.c)
set(SNIFFSD sniffd)
set(CMAKE_CXX_STANDARD 11)
include(FindPCAP.cmake)

add_executable(${SNIFFSD} ${SOURCE_SNIFFSD})
target_link_libraries(${SNIFFSD} ${PCAP_LIBRARY})

set(SOURCE_INTFCD ./sources/intfcd.c)
set(INTFCD intfcd)

add_executable(${INTFCD} ${SOURCE_INTFCD})
