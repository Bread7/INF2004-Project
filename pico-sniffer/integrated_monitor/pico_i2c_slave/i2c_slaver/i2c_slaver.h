#ifndef I2C_SLAVE_COMMUNICATION_H
#define I2C_SLAVE_COMMUNICATION_H

#include <i2c_fifo.h>
#include <i2c_slave.h>
#include <pico/stdlib.h>
#include <stdio.h>
#include <string.h>

#define I2C_SLAVE_ADDRESS 0x42
#define I2C_BAUDRATE 400000
#define I2C_SLAVE_SDA_PIN PICO_DEFAULT_I2C_SDA_PIN
#define I2C_SLAVE_SCL_PIN PICO_DEFAULT_I2C_SCL_PIN

extern char *send_string;
extern size_t send_string_len;

typedef struct {
    uint8_t mem_address;
} I2CSlaveContext;

void i2c_slave_handler(i2c_inst_t *i2c, i2c_slave_event_t event);
void setup_slave();

#endif // I2C_SLAVE_COMMUNICATION_H
