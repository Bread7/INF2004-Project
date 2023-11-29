cmake_minimum_required(VERSION 3.12)

# Pull in SDK (must be before project)
include(pico_sdk_import.cmake)

include(pico_extras_import_optional.cmake)

project(pico_sniffer C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(PICO_BOARD pico_w)

if (PICO_SDK_VERSION_STRING VERSION_LESS "1.3.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.3.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
endif()

set(PICO_EXAMPLES_PATH ${PROJECT_SOURCE_DIR})
# Change nexmon root value to local nexmon folder
set(NEXMON_ROOT "/Users/zj/Downloads/nexmon")


if(NOT DEFINED NO_NEXMON)
    if(NOT DEFINED NEXMON_ROOT)
        if(DEFINED ENV{NEXMON_ROOT})
            set(NEXMON_ROOT $ENV{NEXMON_ROOT})
            message("Using NEXMON_ROOT from environment ('${NEXMON_ROOT}')")
        else()
            message(FATAL_ERROR "NEXMON_ROOT or NO_NEXMON must be set.")
        endif()
    endif()
    message("NEXMON_ROOT is ${NEXMON_ROOT}")
else()
    message("Force no NEXMON (${NO_NEXMON}).")
endif()
set(PICO_NEXMON_PATH ${PROJECT_SOURCE_DIR})
set(PICO_CYW43_DRIVER_PATH ${PROJECT_SOURCE_DIR}/cyw43-driver)

# Initialize the SDK
pico_sdk_init()


include(example_auto_set_url.cmake)
add_compile_options(-Wall
        -Wno-format          # int != int32_t as far as the compiler is concerned because gcc has int32_t as long int
        -Wno-unused-function # we have some for the docs that aren't called
        )
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-maybe-uninitialized)
endif()


# Hardware-specific examples in subdirectories:

add_compile_options(-Wall
        -Wno-format
        -Wno-unused-function
        -Wno-unused-local-typedefs
        )
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-maybe-uninitialized)
endif()

if (PICO_CYW43_SUPPORTED)
    if (NOT TARGET pico_cyw43_arch)
        message("Pico W support required")
    else()
        # add_subdirectory(monitor_sd_write)
	    # add_subdirectory(monitor_mode)
        add_subdirectory(integrated_monitor)
        # add_subdirectory(netAnalysis)
        # add_subdirectory(sdCard_SPI_FatFS)
        # add_subdirectory(pico_i2c_slave)
        # add_subdirectory(readSDSend)
        # add_subdirectory(i2c_slave)
    endif()
endif()