# Based on the hackrf cmakefiles, in turn based on the libftdi cmake

cmake_minimum_required(VERSION 2.8)
project(userspace-wifi C)
set(PACKAGE userspace-wifi)
include(${PROJECT_SOURCE_DIR}/cmake/set_release.cmake)
add_definitions(-DRELEASE="${RELEASE}")
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

if (MSVC)
    include_directories(getopt)
    add_definitions(/D _CRT_SECURE_NO_WARNINGS)
    if (FIND_DEBUG)
        add_definitions(/D FIND_DEBUG)
    endif()
else()
    add_definitions(-Wall)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
    if (FIND_DEBUG)
        add_definitions(-DFIND_DEBUG=1)
    endif()
endif()

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
    wifi_coconut_capture
    wifi_coconut
)

if (MSVC)
    add_library(libgetopt_static STATIC
        getopt/getopt.c
    )
endif()

LIST(APPEND TOOLS_LINK_LIBS wifiuserspace-static)
LIST(APPEND TOOLS_LINK_LIBS ${INT_THREAD_LIBS})
LIST(APPEND TOOLS_LINK_LIBS ${INT_LIBUSB_LIBS})
LIST(APPEND TOOLS_LINK_LIBS ${CMAKE_THREAD_LIBS_INIT})

include_directories(${PROJECT_SOURCE_DIR})

if (MSVC)
    LIST(APPEND TOOLS_LINK_LIBS libgetopt_static)

    add_custom_target(copydlls)
endif()

add_executable(wifi_coconut_capture 
    wifi_capture.c
)

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

