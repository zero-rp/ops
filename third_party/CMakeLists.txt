#添加代码目录
ADD_SUBDIRECTORY(boringssl)

option(LIBUV_BUILD_SHARED OFF)
ADD_SUBDIRECTORY(libuv)

ADD_SUBDIRECTORY(sqlite)
#lsquic
SET(ZLIB_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/third_party/zlib)
SET(BORINGSSL_DIR ${PROJECT_SOURCE_DIR}/third_party/boringssl)
SET(BORINGSSL_INCLUDE ${PROJECT_SOURCE_DIR}/third_party/boringssl/include)
SET(LSQUIC_TESTS OFF)
SET(LSQUIC_BIN OFF)
ADD_SUBDIRECTORY(lsquic)

if(ANDROID)

else ()
option(ZLIB_BUILD_EXAMPLES OFF)
ADD_SUBDIRECTORY(zlib)
endif ()

add_library(http-parser STATIC
    http-parser/http_parser.c
)


