#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"

// Sd card includes:
#include "sd_card.h"
#include "ff.h"
#include "analyse_packet.h"

// Timer Component
#include "hardware/pwm.h"
#include "hardware/adc.h"

// I2C slave includes:
#include <i2c_fifo.h>
#include <i2c_slave.h>

#define MONITOR_DISABLED 0
#define MONITOR_IEEE80211 1
/* RADIOTAP MODE REQUIRES A NEXMON FW! */
#define MONITOR_RADIOTAP 2
#define MONITOR_LOG_ONLY 16

// Buttons to trigger monitor or read
#define MON_BUTTON 20
#define READ_BUTTON 21

// I2C Slave
static const uint I2C_SLAVE_ADDRESS = 0x42;                     // Master must share the same slave address
static const uint I2C_BAUDRATE = 400000;                        // 100 kHz
static const uint I2C_SLAVE_SDA_PIN = PICO_DEFAULT_I2C_SDA_PIN; // 4
static const uint I2C_SLAVE_SCL_PIN = PICO_DEFAULT_I2C_SCL_PIN; // 5

// Send strings used for I2C to send value to I2C Master
// char *send_string = "tester  Source port : 8 Destination port : 167 Source IP : 192.168.1.35 Destination IP : 8.8.8.8 Source Mac : f4 : a4 : 75 : 86 : f7 : 13 Destination Mac : ec : f4 : 51 : 80 : 32 : a3 ";
static char *send_string = "";
static size_t send_string_len = 200; // Length of the string

// Structure for memory addressed used by I2C
static struct
{
    uint8_t mem_address;
} context = {
    .mem_address = 0};

// Frame type declarations for packet identification used in monitor mode
const char *frame_type_names[3] = {
    "Management",
    "Control",
    "Data"};
const char *frame_subtype_names[4][16] = {
    {"Association Request", "Association Response", "Reassociation Request", "Reassociation Response",
     "Probe Request", "Probe Response", "Timing Advertisement", "Reserved",
     "Beacon", "ATIM", "Disassociation", "Authentication", "Deauthentication", "Action", "Action No Ack (NACK)", "Reserved"},
    {"Reserved", "Reserved", "Trigger[3]", "TACK",
     "Beamforming Report Poll", "VHT/HE NDP Announcement", "Control Frame Extension", "Control Wrapper",
     "Block Ack Request (BAR)", "Block Ack (BA)", "PS-Poll", "RTS", "CTS", "ACK", "CF-End", "CF-End + CF-ACK"},
    {"Data", "Reserved", "Reserved", "Reserved",
     "Null (no data)", "Reserved", "QoS Data", "QoS Data + CF-ACK",
     "QoS Data + CF-Poll", "QoS Data + CF-ACK + CF-Poll", "QoS Null (no data)", "Reserved", "QoS CF-Poll (no data)", "QoS CF-ACK + CF-Poll (no data)", "Reserved", "Reserved"},
    {"DMG Beacon", "S1G Beacon", "Reserved", "Reserved",
     "Reserved", "Reserved", "Reserved", "Reserved",
     "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved"}};

// Global file Variables:
static FRESULT fr;
static FATFS fs;
static FIL fil;
static int ret;                                        // Status flag to check return value during file operations
static char buf[100];                                  // Buffer for reading
static char filename[] = "Packet13.txt";              // Filename that is used for read and writing
char delim[2] = "\n";                                  // Delimiter for splitting packets in txt
char *ptr;                                             // Pointer for each packet
int timeValue;                                         // Time storing variable

// Global Timer Variables
#define TIME_INTERVAL_MS 1000
volatile bool timer_running = true;
volatile int elapsed_time = 0;
volatile int current_time = 0;
static char time_str[20];
struct repeating_timer timer;
static bool mon_running;                               // Check if monitor mode is running
static bool read_running;                              // Check if read mode is running

// Global AP Variables
const char *ap_name = "picow_test";
const char *password = "password";
const uint32_t channels[] = {1, 6, 11};
static volatile uint8_t chan_idx = 0;

// Mode for monitoring/reading
static volatile int mode = 0;                           // 0 for monitoring, 1 for reading

// Buffer size
#define ANALYSE_BUF_SIZE 5000                           // Buffer for analyse in reading mode

// Elapsing timing for captured packets
bool repeating_timer_callback(struct repeating_timer *t)
{
    if (timer_running)
    {
        elapsed_time++;
        return true;
    } else {
        return false;
    }
}

// Conversion function to convert strings to unsigned character array (bytes)
unsigned char *convertStringToBytes(const char *str)
{
    // Calculate the number of bytes in the string
    size_t len = strlen(str) / 3;

    // Allocate memory for the array of bytes
    unsigned char *bytes = (unsigned char *)malloc(len);

    // Check for memory allocation failure
    if (bytes == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Loop through the string and convert each pair of characters
    for (size_t i = 0, j = 0; i < len; i++, j += 3)
    {
        sscanf(str + j, "%2hhx", &bytes[i]);
    }

    return bytes;
}


// Handler for I2C communication
static void i2c_slave_handler(i2c_inst_t *i2c, i2c_slave_event_t event)
{
    switch (event)
    {
    case I2C_SLAVE_REQUEST: // master is requesting data
        // if (strcmp(send_string, "")) {
        //     break;
        // }
        i2c_write_byte(i2c, send_string[context.mem_address]);
        context.mem_address = (context.mem_address + 1) % send_string_len;
        break;
    case I2C_SLAVE_FINISH: // master has signalled Stop / Restart
        context.mem_address = 0;
        break;
    default:
        break;
    }
}

// Setup function for the I2C slave
static void setup_slave()
{
    // Init slave pins
    gpio_init(I2C_SLAVE_SDA_PIN);
    gpio_set_function(I2C_SLAVE_SDA_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SLAVE_SDA_PIN);
    gpio_init(I2C_SLAVE_SCL_PIN);
    gpio_set_function(I2C_SLAVE_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SLAVE_SCL_PIN);
    i2c_init(i2c0, I2C_BAUDRATE);
    i2c_slave_init(i2c0, I2C_SLAVE_ADDRESS, &i2c_slave_handler);
}

// Writes the data value into the file
void write_to_sd(char *data)
{
    // Open file for writing
    fr = f_open(&fil, filename, FA_OPEN_APPEND | FA_WRITE);
    if (fr != FR_OK)
    {
        printf("ERROR: Could not open file (%d)\r\n", fr);
        return;
    }
    // Write the data into file
    ret = f_puts(data, &fil);
    if (ret < 0)
    {
        printf("ERROR: Could not write to file (%d)\r\n", ret);
        f_close(&fil);
        return;
    }

    fr = f_close(&fil);
    if (fr != FR_OK)
    {
        printf("ERROR: Could not close file (%d)\r\n", fr);
        return;
    }
}

// Monitoring callback to capture packets and write to SD card
void monitor_mode_cb(void *data, int itf, size_t len, const uint8_t *buf)
{
    uint16_t offset_80211 = 0;
    if (cyw43_state.is_monitor_mode == MONITOR_RADIOTAP)
        offset_80211 = *(uint16_t *)(buf + 2);
    uint8_t frame_type = buf[offset_80211] >> 2 & 3;
    uint8_t frame_subtype = buf[offset_80211] >> 4;
    // Log Data Buffer
    char log_data[1024];
    int log_data_len = 0;
    // Only get packets type (data)
    if (frame_type == 2)
    {
        // Ensure that the len of each packet is under 60
        if (len >= 60)
        {
            printf("Frame type=(%s) subtype=%d (%s) len=%d\n", frame_type_names[frame_type], frame_subtype, frame_subtype_names[frame_type][frame_subtype], len);
            // Loop through packet bytes and save it into log_data
            for (size_t i = 4; i < 60; ++i)
            {
                log_data_len += snprintf(log_data + log_data_len, sizeof(log_data) - log_data_len, "%02x ", buf[i]);
            }
            current_time = elapsed_time;            
            sprintf(time_str, "%d", current_time);
            strcat(log_data, time_str);
            // printf("\nTime %d\n", elapsed_time);
            strcat(log_data, "\n");
            // Uncomment for testing
            printf("%s\n\n", log_data);

            // Save to file
            write_to_sd(log_data);

            // Set the I2C string for telegram bot
            unsigned char* i2c_string;
            strncpy((char *)i2c_string, log_data, log_data_len);
            send_string = packetCheck(i2c_string, current_time);
            // printf("\n==============\n%s\n==============\n", send_string);  // comment this line out to stop printing during monitoring
            busy_wait_us(1500);                                             // This needs to be long enough so the send data does not corrupt
        }
    }
    return;
}

void sd_mount_init()
{
    // Initialize SD card
    if (!sd_init_driver())
    {
        printf("ERROR: Could not initialize SD card\r\n");
        return;
    }

    // Mount drive
    fr = f_mount(&fs, "0:", 1);
    if (fr != FR_OK)
    {
        printf("ERROR: Could not mount filesystem (%d)\r\n", fr);
        return;
    }
}

// Read from file and print the analysed values
// using Pico's second core via multicore
void read_from_file()
{
    // Give 5000 sized buffer incase the file is to big, can be adjusted accordingly
    char *analyse_buf = (char *)calloc(ANALYSE_BUF_SIZE, sizeof(char)); 

    fr = f_open(&fil, filename, FA_READ);
    printf("\r\n---\r\n");
    while (f_gets(buf, 100, &fil))
    {
        strcat(analyse_buf, buf);
    }
    // Break the string by \n and translate them
    ptr = strtok(analyse_buf, delim);
    while (ptr != NULL)
    {
        // Convert value of ptr to unsigned char
        unsigned char *packet = convertStringToBytes(ptr);
        
        // Time
        timeValue = strtol(ptr + 168, NULL, 10);
        printf("\ntime:%d\n",timeValue); // 56 *3

        // Analyse
        char *result = packetCheck(packet, timeValue);
        printf("%s\n", result);

        // Free Results
        free(result);
        ptr = strtok(NULL, delim);
    }
    free(analyse_buf);

    fr = f_close(&fil);
    if (fr != FR_OK)
    {
        printf("ERROR: Could not close file (%d)\r\n", fr);
        return;
    }
    printf("\r\n---\r\nCompleted reading, press Read button to read next packet or press Monitor button to start monitoring again.\r\n");
}

// Handle Interrupt Service
void ButtonEvent_IRQ(uint gpio, uint32_t events)
{
    if (gpio == MON_BUTTON)
    {
        // If monitor isnt running
        if (!mon_running && !read_running)
        {
            mon_running = true;
            printf("Starting monitoring, stopping reading.\n");

            // initialise the cyw43 arch to start monitor mode
            cyw43_set_monitor_mode(&cyw43_state, MONITOR_IEEE80211, monitor_mode_cb);
            mode = 0;
        }
        // if already running
        else
        {
            printf("Monitor mode is already running\n");
        }
    } else if (gpio == READ_BUTTON)
    {

        // If monitor mode running and not currently reading file, 
        // then perform kill task and init the read task
        if (mon_running && !read_running)
        {
            printf("Starting reading, stopping monitoring.\n");
            // Set monitor mode to be false
            mon_running = false;
            read_running = true;
            mode = 1;

            // Kill monitor mode and start read sending
            cyw43_set_monitor_mode(&cyw43_state, MONITOR_DISABLED, monitor_mode_cb);

            if (fr != FR_OK)
            {
                printf("File is closed\r\n", fr);
            }
            else
            {
                // File was still open, close it first
                fr = f_close(&fil);
            }
        }
        // Execute reading on second core to avoid IRQ assertion on core 0
        multicore_reset_core1();
        multicore_launch_core1(read_from_file);
        read_running = false;
    }
}

// Init the buttons for controlling the mode
void initButton()
{
    // GPIO buttons initialise
    gpio_init(MON_BUTTON);
    gpio_init(READ_BUTTON);

    // Set BUTTONs as INPUT
    gpio_set_dir(MON_BUTTON, GPIO_IN);
    gpio_set_dir(READ_BUTTON, GPIO_IN);

    // Pull Down By Default as indicated by Maker PI
    gpio_set_pulls(MON_BUTTON, false, true);
    gpio_set_pulls(READ_BUTTON, false, true);
}

int main()
{
    // Initialise necessary drivers and libraries
    stdio_init_all();
    initButton();
    setup_slave();
    sd_mount_init();

    // Timer implementation
    add_repeating_timer_ms(TIME_INTERVAL_MS, repeating_timer_callback, NULL, &timer);

    sleep_ms(10000);
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
    }
    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_WPA2_AES_PSK);
    cyw43_set_monitor_mode(&cyw43_state, MONITOR_IEEE80211, monitor_mode_cb);
    mon_running = true;
    read_running = false;

    // Initialize monitoring and reading button for interrupt
    gpio_set_irq_enabled_with_callback(MON_BUTTON, GPIO_IRQ_EDGE_RISE, true, &ButtonEvent_IRQ);
    gpio_set_irq_enabled_with_callback(READ_BUTTON, GPIO_IRQ_EDGE_RISE, true, &ButtonEvent_IRQ);

    printf("Starting monitoring!\n");

    // Loop monitoring during monitor mode
    while (true) {
        if (mode == 0) {
            cyw43_wifi_ap_set_channel(&cyw43_state, channels[chan_idx]);
            chan_idx = (chan_idx + chan_idx) % (sizeof(channels) / sizeof(channels[0]));
            sleep_ms(500);
        }
        // tight_loop_contents();
    }
    // Unmount drive and uninitialise cyw43 driver
    f_unmount("0:");
    cyw43_arch_deinit();
    return 0;
}