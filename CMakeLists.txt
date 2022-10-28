# Based on the hackrf cmakefiles, in turn based on the libftdi cmake

cmake_minimum_required(VERSION 3.0)

if (MSVC)
    include_directories(getopt)
    add_definitions(/D _CRT_SECURE_NO_WARNINGS)
    if (FIND_DEBUG)
        add_definitions(/D FIND_DEBUG)
    endif()
elseif (MINGW32)
    set(CMAKE_SYSTEM_NAME Windows)
    set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
    set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
    set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
    set(CMAKE_Fortran_COMPILER ${TOOLCHAIN_PREFIX}-gfortran)
    set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
    set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
else()
    add_definitions(-Wall)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
    if (FIND_DEBUG)
        add_definitions(-DFIND_DEBUG=1)
    endif()
endif()

project(userspace-wifi C)
set(PACKAGE userspace-wifi)
include(${PROJECT_SOURCE_DIR}/cmake/set_release.cmake)
add_definitions(-DRELEASE="${RELEASE}")
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

set(prefix ${CMAKE_INSTALL_PREFIX})

if(MSVC)
    find_package(PThread REQUIRED)
    include_directories(${PTHREAD_INCLUDE_DIR}) 
    set(INT_THREAD_LIBS ${PTHREADS_LIBRARY})

    find_package(LibUSB-1.0 REQUIRED)
    include_directories(${LIBUSB_1_INCLUDE_DIR})
    link_directories(${LIBUSB_1_LIBRARY_DIR})
    set(INT_LIBUSB_LIBS ${LIBUSB_1_LIBRARIES})

    set (firmwaredir .)
elseif(MINGW32)
    # find_package(PThread REQUIRED)
    # include_directories(${PTHREAD_INCLUDE_DIR}) 
    # set(INT_THREAD_LIBS ${PTHREADS_LIBRARY})

    #find_package(LibUSB-1.0 REQUIRED)
    #include_directories(${LIBUSB_1_INCLUDE_DIR})
    #link_directories(${LIBUSB_1_LIBRARY_DIR})
    #set(INT_LIBUSB_LIBS ${LIBUSB_1_LIBRARIES})

    find_package(Threads REQUIRED)
    set(INT_THREAD_LIBS ${THREADS_LIBRARY})

    include_directories("${VCPKG_HOME}/installed/x64-mingw-static/include/libusb-1.0")
    set(INT_LIBUSB_LIBS "${VCPKG_HOME}/installed/x64-mingw-static/lib/libusb-1.0.a")

    set (firmwaredir .)
else()
    find_package(Threads REQUIRED)
    set(INT_THREAD_LIBS ${THREADS_LIBRARY})

    find_package(USB1 REQUIRED)
    include_directories(${LIBUSB_INCLUDE_DIR})
    set(INT_LIBUSB_LIBS ${LIBUSB_LIBRARIES})

    set (firmwaredir \${prefix}/share/wifiuserspace/firmware)

endif()


add_subdirectory(libwifiuserspace)

include_directories(${PROJECT_SOURCE_DIR}/libwifiuserspace)

SET(TOOLS
    wifi_coconut
)

if (MSVC)
    add_library(libgetopt_static STATIC
        getopt/getopt.c
    )
endif()

if (MINGW32)
    add_library(libpthread STATIC IMPORTED)
else()
    LIST(APPEND TOOLS_LINK_LIBS ${INT_THREAD_LIBS})
endif()

LIST(APPEND TOOLS_LINK_LIBS wifiuserspace-static)
LIST(APPEND TOOLS_LINK_LIBS ${INT_LIBUSB_LIBS})
LIST(APPEND TOOLS_LINK_LIBS ${CMAKE_THREAD_LIBS_INIT})

include_directories(${PROJECT_SOURCE_DIR})

if (MSVC)
    LIST(APPEND TOOLS_LINK_LIBS libgetopt_static)

    add_custom_target(copydlls)
endif()

add_executable(wifi_coconut 
    wifi_coconut.c 
    wifi_coconut/wifi_coconut.c
)

foreach(tool ${TOOLS})
    target_link_libraries(${tool} ${TOOLS_LINK_LIBS})
    install(TARGETS ${tool} RUNTIME DESTINATION bin)
endforeach(tool)

INSTALL(
    DIRECTORY ${PROJECT_SOURCE_DIR}/libwifiuserspace/firmware/
    DESTINATION ${firmwaredir}
)

