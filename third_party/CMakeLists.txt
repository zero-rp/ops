#添加代码目录
ADD_SUBDIRECTORY(boringssl)

option(LIBUV_BUILD_SHARED OFF)
ADD_SUBDIRECTORY(libuv)

ADD_SUBDIRECTORY(sqlite)

if(!ANDROID)
option(ZLIB_BUILD_EXAMPLES OFF)
ADD_SUBDIRECTORY(zlib)
endif ()

add_library(http-parser STATIC
    http-parser/http_parser.c
)


