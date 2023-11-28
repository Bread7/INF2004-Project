add_executable(integrated_monitor
        integrated_monitor.c
        hw_config.c
        analyse_packet.c
        )
target_include_directories(integrated_monitor PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )
target_link_libraries(integrated_monitor
        pico_cyw43_arch_lwip_threadsafe_background
        pico_stdlib
        FatFs_SPI2
        hardware_adc
        hardware_irq
        hardware_pwm
        # I2C Slave
        i2c_slave
        # Multicore
        pico_multicore
        )

# Ucomment when using NEXMON driver
target_compile_definitions(integrated_monitor PRIVATE
        CYW43_CHIPSET_FIRMWARE_INCLUDE_FILE="${NEXMON_ROOT}/patches/bcm43439a0/7_95_49_2271bb6/nexmon/w43439A0_7_95_49_00_combined.h"
        CYW43_WIFI_NVRAM_INCLUDE_FILE="${PICO_NEXMON_PATH}/cyw43-driver/firmware/wifi_nvram_43439.h"
        # CYW43_ENABLE_BLUETOOTH=0
        PICO_MAX_SHARED_IRQ_HANDLERS=5
        )

pico_add_extra_outputs(integrated_monitor)
pico_enable_stdio_usb(integrated_monitor TRUE)
pico_enable_stdio_uart(integrated_monitor TRUE)
