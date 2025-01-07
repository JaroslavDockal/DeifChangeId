import tkinter as tk
from tkinter import messagebox, scrolledtext
import can
import os
import logging

# Global definition of the logger
logger = logging.getLogger()


def setup_logger(text_widget):
    """
    Configure the logger to output to both the console and a GUI text widget.

    :param text_widget: The Tkinter Text widget to display log messages.
    """
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler for ERROR and higher
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # GUI handler for all levels
    gui_handler = TextHandler(text_widget)
    gui_handler.setLevel(logging.DEBUG)
    gui_handler.setFormatter(formatter)
    logger.addHandler(gui_handler)


class TextHandler(logging.Handler):
    """Custom logging handler that sends logs to a Tkinter Text widget."""

    def __init__(self, text_widget):
        """
        Initialize the handler.

        :param text_widget: The Tkinter Text widget to display log messages.
        """
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        """Output the log message to the text widget."""
        msg = self.format(record)
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.configure(state='disabled')
        self.text_widget.yview(tk.END)


def detect_interfaces(default_type='ixxat'):
    """
    Detect available CAN interfaces, focusing on a specific type, defaulting to 'ixxat'.

    :param default_type: Preferred interface type to detect.
    :return: List of interfaces of the default type or a message if none found.
    """
    available_interfaces = can.detect_available_configs()
    logger.debug(f"Detected interfaces: {available_interfaces}")
    ixxat_interfaces = [f"{config['interface']}:{config['channel']}" for config in available_interfaces if
                        config['interface'].lower() == default_type]
    return ixxat_interfaces if ixxat_interfaces else ["None found"]


def refresh_interfaces(interface_dropdown):
    """
    Refresh the dropdown menu of CAN interfaces.

    :param interface_dropdown: The Tkinter OptionMenu widget for selecting interfaces.
    """
    interfaces = detect_interfaces()
    menu = interface_dropdown['menu']
    menu.delete(0, 'end')  # Delete old items
    for interface in interfaces:
        menu.add_command(label=interface, command=lambda value=interface: interface_choice.set(value))
    logger.info("Interface list refreshed.")


def send_can_message(bus_type, channel, cob_id, data):
    """
    Send a CAN message via the specified bus.

    :param bus_type: The type of CAN bus.
    :param channel: The channel on which to send the message.
    :param cob_id: The COB-ID of the CAN message.
    :param data: The data payload of the CAN message.
    """
    os.add_dll_directory("C:\\Windows\\System32")
    os.add_dll_directory("C:\\Windows\\SysWOW64")
    bus = None
    try:
        bus = can.interface.Bus(channel=channel, interface=bus_type)
        message = can.Message(arbitration_id=cob_id, data=data, is_extended_id=False)
        bus.send(message)
        logger.info(f"Message successfully sent to {hex(cob_id)}")
        logger.info(f"Message data {data}")
    except Exception as e:
        logger.error("Message NOT sent", exc_info=True)
    finally:
        if bus:
            bus.shutdown()  # Properly shut down the connection to the CAN device
            logger.info("CAN bus successfully shut down.")


def create_message(change_type, interface):
    """
    Create and send a CAN message based on the specified change type ('change' or 'save').

    :param change_type: Specifies the operation, either 'change' or 'save'.
    :param interface: The selected CAN interface.
    """
    # Check if an interface is selected
    if ':' not in interface:
        logger.warning("No interface selected. Please select a valid interface.")
        return

    # Validate the input values of Existing S-ID and New S-ID
    try:
        existing_sid = int(existing_id.get())
        new_sid = int(new_id.get())
    except ValueError:
        messagebox.showerror("Input Error", "Please enter valid numeric values for S-ID fields.")
        logger.error("Invalid S-ID input. Both Existing S-ID and New S-ID must be valid integers.")
        return

    # Calculate COB-ID and prepare data
    cob_id = 0x200 + (existing_sid if change_type == 'change' else new_sid)
    data = [0xFF, 0x00, 0x28, 0x00, new_sid, 0x00, 0x00, 0x00] if change_type == 'change' else [0xFF, 0x00, 0x29, 0x00, 0x73, 0x61, 0x76, 0x65]

    # Send the message
    bus_type, channel = interface.split(':')
    send_can_message(bus_type, channel, cob_id, data)


def setup_ui():
    """
    Set up the user interface for the CAN controller.
    """
    root = tk.Tk()
    root.title("CAN Interface Controller")
    root.geometry("800x600")

    # Variables
    global existing_id, new_id, interface_choice
    existing_id, new_id, interface_choice = tk.StringVar(), tk.StringVar(), tk.StringVar()

    # Text widget for logging
    log_text_widget = scrolledtext.ScrolledText(root, state='disabled', height=10)
    log_text_widget.grid(row=5, column=0, columnspan=2, sticky='nsew', padx=10, pady=10)

    # Setup logger with the GUI text widget
    setup_logger(log_text_widget)

    # Layout of components in the GUI
    tk.Label(root, text="Select Interface:").grid(row=0, column=0, padx=10, pady=5, sticky="ew")
    interface_dropdown = tk.OptionMenu(root, interface_choice, *detect_interfaces())
    interface_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

    # Button to refresh available interfaces
    tk.Button(root, text="Refresh Interfaces", command=lambda: refresh_interfaces(interface_dropdown)).grid(
        row=1, column=1, padx=10, pady=5, sticky="ew"
    )

    tk.Label(root, text="Existing S-ID:").grid(row=2, column=0, padx=10, pady=5, sticky="ew")
    tk.Entry(root, textvariable=existing_id).grid(row=2, column=1, padx=10, pady=5, sticky="ew")

    tk.Label(root, text="New S-ID:").grid(row=3, column=0, padx=10, pady=5, sticky="ew")
    tk.Entry(root, textvariable=new_id).grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    tk.Button(root, text="Send Change ID Message",
              command=lambda: create_message('change', interface_choice.get())).grid(row=4, column=0, padx=10, pady=5,
                                                                                     sticky="ew")
    tk.Button(root, text="Send Save ID Message", command=lambda: create_message('save', interface_choice.get())).grid(
        row=4, column=1, padx=10, pady-5, sticky="ew")

    # Configuration for dynamic layout of log widget
    root.grid_rowconfigure(5, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    root.mainloop()


if __name__ == "__main__":
    setup_ui()
