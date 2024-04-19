cmake_minimum_required(VERSION 3.4.1)

project(ops)

set(CMAKE_EXE_LINKER_FLAGS "-static")

#添加包含目录
include_directories(third_party/boringssl/include)
include_directories(third_party/libuv/include)
include_directories(third_party/http-parser)
include_directories(third_party/cJSON)
include_directories(third_party/sqlite)
#查找线程库
find_package(Threads)

#添加代码目录
ADD_SUBDIRECTORY(third_party)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()
#生成
add_executable(ops
    src/ops.c
    src/sds.c
    src/databuffer.c
    src/data.c
    third_party/cJSON/cJSON.c
    third_party/cJSON/cJSON_Utils.c
)
target_link_libraries(ops uv_a http-parser sqlite crypto zlibstatic ${LIBS})
add_executable(opc
    src/opc.c
    src/sds.c
    src/databuffer.c
    third_party/cJSON/cJSON.c
    third_party/cJSON/cJSON_Utils.c
)
target_link_libraries(opc uv_a zlibstatic ${LIBS})

