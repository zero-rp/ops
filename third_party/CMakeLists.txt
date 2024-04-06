#添加代码目录
ADD_SUBDIRECTORY(libuv)
ADD_SUBDIRECTORY(sqlite)
add_library(http-parser STATIC
    http-parser/http_parser.c
)


