cmake_minimum_required(VERSION 3.4.1)

project(ops)

#
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")


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

#生成
add_executable(ops
    src/ops.c
	src/sds.c
	src/databuffer.c
	src/data.c
)
target_link_libraries(ops uv http-parser sqlite ${LIBS})
add_executable(opc
    src/opc.c
	src/sds.c
	src/databuffer.c
)
target_link_libraries(opc uv ${LIBS})

