import tkinter as tk
from tkinter import messagebox, scrolledtext
import can
import threading
import logging
import time

# Global logger setup
logger = logging.getLogger()

# Variable to stop the sniffing thread
stop_sniffing = threading.Event()


class CANSniffer:
    """Class for sniffing CAN bus messages."""

    def __init__(self, bus_type, channel, text_widget, bitrate=500000):
        """
        Initialize the CANSniffer object.

        :param bus_type: The type of CAN bus interface (e.g., 'socketcan', 'ixxat').
        :param channel: The channel number or identifier for the CAN interface.
        :param text_widget: The tkinter text widget for displaying received messages.
        :param bitrate: The bitrate for the CAN bus.
        """
        self.bus_type = bus_type
        self.channel = channel
        self.text_widget = text_widget
        self.bitrate = bitrate
        self.bus = None

    def start(self):
        """Start the sniffing process on the CAN bus."""
        try:
            self.bus = can.interface.Bus(
                channel=self.channel,
                interface=self.bus_type,
                bitrate=self.bitrate,
                receive_own_messages=False  # Do not listen to own messages
            )
            if not self.bus:
                logger.error("Failed to initialize CAN bus. Check device and connection.")
                return
            logger.info(f"Sniffer started on {self.bus_type}:{self.channel} with bitrate {self.bitrate}")

            # Start monitoring the bus state in a separate thread
            threading.Thread(target=self.monitor_bus_state, daemon=True).start()

            while not stop_sniffing.is_set():
                try:
                    message = self.bus.recv(1)  # Wait for a message with a timeout of 1 second
                    if message:
                        self.display_message(message)
                except can.interfaces.ixxat.exceptions.VCIError as e:
                    logger.error(f"VCIError occurred while receiving message: {str(e)}")
                    logger.debug("Attempting to recover connection...")
                    self.recover_connection()
                    break
                except Exception as e:
                    logger.error("Unexpected error during message reception", exc_info=True)
                    break
        finally:
            if self.bus:
                self.bus.shutdown()
                logger.info("CAN bus successfully shut down.")

    def monitor_bus_state(self):
        """Regularly check the state of the bus."""
        while not stop_sniffing.is_set():
            if not self.bus:
                logger.error("Bus handle is not valid. Stopping bus state monitoring.")
                return
            try:
                state = self.bus.state
                logger.info(f"Bus state: {state}")
                if state != can.BusState.ACTIVE:
                    logger.warning(f"Bus is not active. Current state: {state}")
            except can.interfaces.ixxat.exceptions.VCIError as e:
                logger.error(f"VCIError while checking bus state: {str(e)}")
                return
            except Exception as e:
                logger.error("Unexpected error while monitoring bus state", exc_info=True)
                return
            time.sleep(5)

    def recover_connection(self):
        """Attempt to recover the connection in case of an error."""
        logger.info("Attempting to recover connection...")
        if self.bus:
            self.bus.shutdown()
        time.sleep(2)  # Pause before reconnecting
        self.start()

    def display_message(self, message):
        """Display a received CAN message in the text widget."""
        msg_text = (
            f"Timestamp: {message.timestamp:.3f}, "
            f"ID: {hex(message.arbitration_id)}, "
            f"Data: {list(message.data)}\n"
        )
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, msg_text)
        self.text_widget.configure(state='disabled')
        self.text_widget.yview(tk.END)


def setup_logger(text_widget):
    """Set up the logger to display messages in the GUI."""
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    gui_handler = TextHandler(text_widget)
    gui_handler.setLevel(logging.DEBUG)
    gui_handler.setFormatter(formatter)
    logger.addHandler(gui_handler)


class TextHandler(logging.Handler):
    """Custom logging handler that sends logs to a Tkinter Text widget."""

    def __init__(self, text_widget):
        """
        Initialize the TextHandler with a Tkinter Text widget.

        :param text_widget: The text widget where logs will be displayed.
        """
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        """Emit a log record to the text widget."""
        msg = self.format(record)
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.configure(state='disabled')
        self.text_widget.yview(tk.END)


def detect_interfaces(default_type='ixxat'):
    """Detect available CAN interfaces focusing on a specified default type."""
    available_interfaces = can.detect_available_configs()
    logger.debug(f"Detected interfaces: {available_interfaces}")
    ixxat_interfaces = [f"{config['interface']}:{config['channel']}" for config in available_interfaces if
                        config['interface'].lower() == default_type]
    return ixxat_interfaces if ixxat_interfaces else ["None found"]


def refresh_interfaces(interface_dropdown):
    """Refresh the list of available interfaces in the dropdown menu."""
    interfaces = detect_interfaces()
    menu = interface_dropdown['menu']
    menu.delete(0, 'end')  # Clear old items
    for interface in interfaces:
        menu.add_command(label=interface, command=lambda value=interface: interface_choice.set(value))
    logger.info("Interface list refreshed.")


def start_sniffing(interface_choice, log_text_widget):
    """Start a thread to sniff CAN bus messages."""
    if ':' not in interface_choice.get():
        messagebox.showerror("Input Error", "Please select a valid interface.")
        return

    bus_type, channel = interface_choice.get().split(':')
    stop_sniffing.clear()
    sniffer = CANSniffer(bus_type, channel, log_text_widget)
    threading.Thread(target=sniffer.start, daemon=True).start()


def stop_sniffing_can():
    """Stop the CAN bus sniffing process."""
    stop_sniffing.set()
    logger.info("Sniffer stopped.")


def setup_ui():
    """Set up the user interface for the CAN sniffer application."""
    root = tk.Tk()
    root.title("CAN Bus Sniffer")
    root.geometry("800x600")

    # Variables
    global interface_choice
    interface_choice = tk.StringVar()

    # Text widget for logs and messages
    log_text_widget = scrolledtext.ScrolledText(root, state='disabled', height=20)
    log_text_widget.grid(row=3, column=0, columnspan=3, sticky='nsew', padx=10, pady=10)

    # Setup logger with GUI text widget
    setup_logger(log_text_widget)

    # GUI components layout
    tk.Label(root, text="Select Interface:").grid(row=0, column=0, padx=10, pady=5, sticky="ew")
    interface_dropdown = tk.OptionMenu(root, interface_choice, *detect_interfaces())
    interface_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

    tk.Button(root, text="Start Sniffing", command=lambda: start_sniffing(interface_choice, log_text_widget)).grid(
        row=1, column=0, padx=10, pady=5, sticky="ew"
    )
    tk.Button(root, text="Stop Sniffing", command=stop_sniffing_can).grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    tk.Button(root, text="Refresh Interfaces", command=lambda: refresh_interfaces(interface_dropdown)).grid(
        row=2, column=0, padx=10, pady=5, sticky="ew"
    )

    # Configuration for dynamic layout of log widget
    root.grid_rowconfigure(3, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    root.grid_columnconfigure(2, weight=1)

    root.mainloop()


if __name__ == "__main__":
    setup_ui()
