add_executable(i2c_slaver i2c_slaver.c)

pico_enable_stdio_uart(i2c_slaver 1)
pico_enable_stdio_usb(i2c_slaver 1)
pico_add_extra_outputs(i2c_slaver)

target_compile_options(i2c_slaver PRIVATE -Wall)

target_link_libraries(i2c_slaver i2c_slave pico_stdlib)
