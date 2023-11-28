add_subdirectory(FatFs_SPI2)
add_subdirectory(pico_i2c_slave)
add_executable(integrated_monitor
        integrated_monitor.c
        ${PICO_LWIP_CONTRIB_PATH}/apps/ping/ping.c
        hw_config.c
        analyse_packet.c
        )
target_include_directories(integrated_monitor PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/../.. # for our common lwipopts
        ${PICO_LWIP_CONTRIB_PATH}/apps/ping
        # FatFs_SPI2
        )
target_link_libraries(integrated_monitor
        pico_cyw43_arch_lwip_threadsafe_background
        pico_stdlib
        pico_lwip_iperf
        hardware_pwm
        hardware_adc
        FatFs_SPI2 
        i2c_slave
        pico_multicore
        )

# add_subdirectory(FatFs_SPI2)
# Ucomment when using NEXMON driver
target_compile_definitions(integrated_monitor PRIVATE
        CYW43_CHIPSET_FIRMWARE_INCLUDE_FILE="${NEXMON_ROOT}/patches/bcm43439a0/7_95_49_2271bb6/nexmon/w43439A0_7_95_49_00_combined.h"
        CYW43_WIFI_NVRAM_INCLUDE_FILE="${PICO_NEXMON_PATH}/cyw43-driver/firmware/wifi_nvram_43439.h"
        # CYW43_ENABLE_BLUETOOTH=0
        NO_SYS=1            # don't want NO_SYS (generally this would be in your lwipopts.h)
        # LWIP_SOCKET=1       # we need the socket API (generally this would be in your lwipopts.h)
        # PING_USE_SOCKETS=1
        PICO_MAX_SHARED_IRQ_HANDLERS=5
        )
pico_add_extra_outputs(integrated_monitor 1)
pico_enable_stdio_usb(integrated_monitor 1)
pico_enable_stdio_uart(integrated_monitor 1)

target_compile_options(integrated_monitor PRIVATE -Wall)
