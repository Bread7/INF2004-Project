import os
import wifi
import socketpool
import time
import microcontroller
import board
import simpleio
import adafruit_requests
import ssl
import busio

class AnomalyDetectorBot:
    NOTE_G4 = 392  # Frequency for G4 note
    NOTE_C5 = 523  # Frequency for C5 note
    
    # Constructor: Initializes I2C, network details, Telegram API, and buzzer settings.
    # Sets up the bot's initial state.
    def __init__(self):
        self.i2c = busio.I2C(scl=board.GP5, sda=board.GP4, frequency=400000)
        self.ssid = os.getenv("WIFI_SSID")
        self.password = os.getenv("WIFI_PASSWORD")
        self.telegrambot = os.getenv("botToken")
        self.api_url = "https://api.telegram.org/bot" + self.telegrambot
        self.buzzer = board.GP18
        self.chat_id = None
        self.first_read = True
        self.update_id = None
        self.i2c_data_enabled = False
        self.wifi_connected = False
        self.init_network()
        self.init_bot()
        
    # Initializes and connects to the WiFi network.
    # Sets up the socketpool and requests session for network communication.
    def init_network(self):
        print("Initializing network connection...")
        wifi.radio.connect(self.ssid, self.password)
        self.pool = socketpool.SocketPool(wifi.radio)
        self.requests = adafruit_requests.Session(self.pool, ssl.create_default_context())
        self.wifi_connected = True
    
    # Checks the WiFi connection status and reconnects if necessary.
    # Ensures the bot maintains an active network connection.
    def check_wifi(self):
        if not wifi.radio.ipv4_address or "0.0.0.0" in repr(wifi.radio.ipv4_address):
            print("Reconnecting to WiFi...")
            wifi.radio.connect(self.ssid, self.password)
            self.wifi_connected = True

    # Initializes the Telegram bot by verifying its credentials.
    # Checks if the bot is properly set up and ready to receive/send messages.
    def init_bot(self):
        response = self.requests.get(self.api_url + "/getMe")
        if not response.json()['ok']:
            print("Telegram bot initialization failed.")
            self.wifi_connected = False
        else:
            print("Telegram bot ready!")
            
    # Reads data from an I2C device at the specified address.
    # Locks the I2C bus, reads the data, then unlocks the bus.
    def read_i2c_data(self, address=0x42):
        while not self.i2c.try_lock():
            pass
        try:
            data = bytearray(200) #Array Size Declaration
            self.i2c.readfrom_into(address, data)
            return data.decode('utf-8')
        finally:
            self.i2c.unlock()

    # Fetches messages from Telegram, using the /getUpdates endpoint.
    # Handles message retrieval, including processing API responses and error handling.
    def read_message(self):
        get_url = self.api_url + "/getUpdates?limit=1&allowed_updates=[\"message\",\"callback_query\"]"
        if not self.first_read:
            get_url += "&offset={}".format(self.update_id)
        response = self.requests.get(get_url)

        try:
            response_json = response.json()
            self.update_id = response_json['result'][0]['update_id']
            message = response_json['result'][0]['message']['text']
            self.chat_id = response_json['result'][0]['message']['chat']['id']
            self.first_read = False
            self.update_id += 1
            simpleio.tone(self.buzzer, AnomalyDetectorBot.NOTE_G4, duration=0.1)
            simpleio.tone(self.buzzer, AnomalyDetectorBot.NOTE_C5, duration=0.1)
            return self.chat_id, message
        except (IndexError, KeyError) as e:
            return False, False
        
    # Sends a message to a user on Telegram.
    # Constructs the request URL and makes a network call to the Telegram API.
    def send_message(self, message):
        send_url = self.api_url + f"/sendMessage?chat_id={self.chat_id}&text={message}"
        self.requests.get(send_url)
    
    # The main loop of the bot.
    # Continuously checks for messages and handles I2C data if enabled.
    def run(self):
        while True:
            if not self.wifi_connected:
                self.check_wifi()
            chat_id, message_in = self.read_message()
            if chat_id:
                self.handle_message(message_in)

            if self.i2c_data_enabled:
                self.handle_i2c_data()

            time.sleep(1)
            
    # Processes incoming Telegram messages and triggers appropriate responses.
    # Handles the commands for /start, /Detect, and /endDetect.
    def handle_message(self, message):
        if message == "/start":
            self.send_welcome_message()
        elif message == "/Detect":
            self.i2c_data_enabled = True
            self.send_message("Network Anomaly detection started.")
        elif message == "/endDetect":
            self.i2c_data_enabled = False
            self.send_message("Network Anomaly detection stopped.")

    # Sends a welcome message with a list of commands to the user.
    # Useful for guiding users on how to interact with the bot.
    def send_welcome_message(self):
        commands = [
            "Welcome to Anomaly Detector Bot!",
            "Choose from one of the following options:",
            "1) Begin Network Monitor: /Detect",
            "2) End Network Monitor: /endDetect"
        ]
        for command in commands:
            self.send_message(command)
            
    # Handles I2C data processing.
    # Intended for detecting and reporting anomalies in the I2C data stream.
    def handle_i2c_data(self):
        i2c_data = self.read_i2c_data()
        # For display on thonny
        print("=======")
        print(i2c_data)
        print("=======")
        # Split data up by \n and send them to tele bot for output
        anomalous_packets = i2c_data.split("\n")
        self.send_message("========Start of Packet Description========")
        for packet in anomalous_packets:
            self.send_message(f"{packet}")
        self.send_message("========End of Packet Description========")

# Initialize and run the bot
bot = AnomalyDetectorBot()
bot.run()

