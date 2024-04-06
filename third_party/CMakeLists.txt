#添加代码目录
set(BUILD_SHARED_AND_STATIC_LIBS on)
ADD_SUBDIRECTORY(cJSON)
ADD_SUBDIRECTORY(libuv)
ADD_SUBDIRECTORY(sqlite)
add_library(http-parser STATIC
    http-parser/http_parser.c
)


