PySniff 🐍
__________________________________________________________________

Dive into your network's traffic with PySniff built in Python.


PySniff captures and decodes network packets in real-time, presenting them in a clean, human-readable format right in your terminal. 

___________________________________________________________________

📌 Features

  1. Live Packet Capture: Watch network traffic as it happens from any of your network interfaces.
  2. Multi-Layer Parsing: Automatically decodes Ethernet, IP, TCP, and UDP headers so you don't have to.
  3. Detailed Payload View: Inspect the actual data being sent in a clean hexadecimal and ASCII layout.
  4. Save for Later: Export your capture session to a .pcap file and analyze it later in tools like Wireshark.
  5.Flexible Controls: Use command-line arguments to specify the packet count, capture duration, and output file.

_____________________________________________________________________

🚀 Prerequisites

1. Python 3.7+
2. Pip (Python's package installer)
3. Administrator/root access on your machine.

______________________________________________________________________
🛠 Installation
Setting up PySniff is quick and easy. Just follow these steps in your terminal:

Clone the repository:
>>git clone https://github.com/elencus/pysniff.git

Navigate into the project folder:
>>cd pysniff

Install the required packages:
>>pip install -r requirements.txt
_____________________________________________________________________

💻 Usage

First, you'll be prompted to select a network interface. Then, the capture will begin based on your command-line arguments.

Basic Usage
To start a simple, unlimited capture session:

On Linux / macOS:
>>sudo python3 main.py

On Windows (run in an Administrator terminal):
>>python main.py

 Advanced Usage with CLI Options, you can control the capture session with the following arguments:
 --count: The number of packets to capture.
 --timeout: The duration in seconds to run the capture.
 --save: The filename for saving the capture (.pcap).

Example: Capture 100 packets and save them to capture.pcap
>>sudo python3 main.py --count 100 --save my_capture.pcap

Example: Capture packets for 60 seconds.
>>sudo python3 main.py --timeout 60

#To stop a capture at any time, simply press Ctrl+C.
