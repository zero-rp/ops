cmake_minimum_required(VERSION 3.4.1)

project(ops)

# 忽略特定的警告
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4996 /wd4819")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996 /wd4819")
  foreach(flag_var
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
    string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif(${flag_var} MATCHES "/MD")
  endforeach(flag_var)
endif()
set(CMAKE_EXE_LINKER_FLAGS "-static")

option(USE_QUIC "quic" OFF)

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
            src/opc/opc.c
            src/common/sds.c
            src/common/obj.c
            src/common/databuffer.c
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
            src/opc/module/forward.c 
            src/opc/module/vpc.c 
            src/opc/module/dst.c
            src/opc/bridge.c
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
            src/ops/bridge.c
            src/ops/http.c
            src/ops/web.c
            src/ops/public.c
            src/ops/module/forward.c
            src/ops/module/dst.c
            src/ops/module/vpc.c
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
    )
    target_link_libraries(ops uv_a llhttp_static sqlite ssl crypto decrepit ${LIBS} zlibstatic)

    add_executable(opc
            src/opc/opc.c
            src/common/sds.c
            src/common/obj.c
            src/common/databuffer.c
            third_party/cJSON/cJSON.c
            third_party/cJSON/cJSON_Utils.c
            src/opc/module/forward.c 
            src/opc/module/vpc.c 
            src/opc/module/dst.c
            src/opc/bridge.c
    )
    target_link_libraries(opc uv_a ssl crypto decrepit ${LIBS} zlibstatic)
endif ()


