cmake_minimum_required(VERSION 3.4.1)

project(ops)

# 忽略特定的警告
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4996 /wd4819")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996 /wd4819")
endif()

set(CMAKE_EXE_LINKER_FLAGS "-static")

option(USE_QUIC "quic" ON)

if(USE_QUIC)
    add_definitions(-DHAVE_QUIC)
    set(LIBS lsquic)
endif()


#添加包含目录
include_directories(src/)
include_directories(third_party/boringssl/include)
include_directories(third_party/libuv/include)
include_directories(third_party/http-parser)
include_directories(third_party/cJSON)
include_directories(third_party/sqlite)
include_directories(${CMAKE_BINARY_DIR}/third_party/zlib)
include_directories(third_party/lsquic/include)
if(WIN32)
include_directories(third_party/lsquic/wincompat)
endif()
#查找线程库
find_package(Threads)

#添加代码目录
ADD_SUBDIRECTORY(third_party)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()
#生成
if(ANDROID)
    add_library(opc SHARED
            src/opc.c
            src/sds.c
			src/obj.c
            src/databuffer.c
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
            )
    target_link_libraries(opc
            uv_a
            z
            android
            log
			ssl
			crypto
			decrepit
			${LIBS}
			)
else ()
    add_executable(ops
            src/common/sds.c
            src/common/databuffer.c
            src/ops/ops.c
            src/ops/data.c
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
            )
    target_link_libraries(ops uv_a http-parser sqlite ssl crypto decrepit ${LIBS} zlibstatic)

    add_executable(opc
            "src/opc/opc.c"
            "src/common/sds.c"
            src/obj.c
            "src/common/databuffer.c"
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
            )
    target_link_libraries(opc uv_a ssl crypto decrepit ${LIBS} zlibstatic)
endif ()


