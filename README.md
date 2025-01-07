
# CAN Interface Monitoring and Control

## Overview
This project consists of two main Python applications for interacting with CAN (Controller Area Network) interfaces using a graphical user interface (GUI) created with tkinter. The applications allow for the monitoring of CAN traffic and controlling CAN device settings through the GUI.

### Features
- **CAN Message Monitoring**: Continuously monitor CAN bus traffic and display messages in real-time.
- **Control CAN Interfaces**: Send specific commands to CAN devices to modify their settings or control their operations.
- **Log System Activities**: Both applications have integrated logging systems that display logs directly in the GUI for easy monitoring and debugging.
- **Dynamic Interface Detection**: Automatically detect and display available CAN interfaces.

## Applications

### 1. CAN Interface Controller
This application provides a GUI for sending commands to CAN interfaces. It allows users to select a CAN interface, send messages, and monitor the success or failure of these operations.

#### Running the Application
To run the CAN Interface Controller, execute the following command in the terminal:
```bash
python ChangeId.py
```

### 2. CAN Bus Sniffer
The CAN Bus Sniffer application is designed to monitor and log CAN bus traffic. Users can start and stop the sniffing process and view the traffic through a straightforward GUI.

#### Running the Application
To run the CAN Bus Sniffer, execute the following command in the terminal:
```bash
python Sniffer.py
```

## Installation
To use these applications, you need to have Python installed on your machine along with the `tkinter` and `python-can` libraries. If not already installed, you can install them using pip:

```bash
pip install python-can tk
```

## Usage
1. Open the terminal.
2. Navigate to the directory where the scripts are located.
3. Run the desired script as mentioned above.
4. Use the GUI to interact with the CAN interfaces.

## Dependencies
- Python 3.11 or higher
- tkinter
- python-can

## License
This project is licensed under the MIT License - see the LICENSE file for details.
