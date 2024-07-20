
```markdown
# Network Scanner

Network Scanner is a Python-based GUI application that allows users to scan a network for devices, retrieve their IP and MAC addresses, and optionally gather additional information such as device names and vendors. The application uses the `scapy` library for network scanning and `tkinter` for the graphical user interface.

## Features

- **Basic Scan**: Retrieve IP and MAC addresses of devices in the specified IP range.
- **Advanced Scan**: In addition to IP and MAC addresses, retrieve device names and vendor information.
- **Copy Functionality**: Right-click on any cell in the results to copy its value to the clipboard.

## Requirements

- Python 3.x
- scapy
- requests
- threading (built-in with Python)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/a6s1/Scan.git
    cd network-scanner
    ```

2. Install the required Python packages:
    ```bash
    pip install scapy requests
    ```

## Usage

1. Run the application:
    ```bash
    python scan.py
    ```

2. Enter the IP ranges to scan (comma separated, e.g., `192.168.1.0/24, 192.168.2.0/24`).

3. Click on "Basic Scan" for a quick scan or "Advanced Scan" for detailed information.

4. Right-click on any cell in the results to copy its value to the clipboard.



## Acknowledgments

- [scapy](https://github.com/secdev/scapy) - A powerful Python library for network packet manipulation.
- [requests](https://github.com/psf/requests) - A simple HTTP library for Python.
- [tkinter](https://docs.python.org/3/library/tkinter.html) - The standard Python interface to the Tk GUI toolkit.


```
