import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp, conf
import socket
import requests
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter

# Function to get vendor information from MAC address
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

# Function to get device name using reverse DNS lookup
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

def scan_network(ip_ranges, advanced=False):
    devices = []
    for subnet in ip_ranges.split(','):
        # Trim any leading or trailing whitespace
        subnet = subnet.strip()
        # Create an ARP request packet
        arp_request = ARP(pdst=subnet)
        # Create an Ethernet frame
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the ARP request and Ethernet frame
        arp_request_broadcast = broadcast / arp_request
        # Send the packet and capture the responses
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            device_info = {'ip': ip, 'mac': mac}
            if advanced:
                device_info['name'] = get_device_name(ip)
                device_info['vendor'] = get_vendor(mac)
            devices.append(device_info)
    
    return devices

def display_devices(devices, tree, advanced=False):
    for row in tree.get_children():
        tree.delete(row)
    for device in devices:
        if advanced:
            tree.insert("", "end", values=(device['ip'], device['mac'], device.get('name', 'Unknown'), device.get('vendor', 'Unknown')))
        else:
            tree.insert("", "end", values=(device['ip'], device['mac']))

def update_charts(devices):
    for widget in chart_frame.winfo_children():
        widget.destroy()
    
    # Count devices by vendor
    vendors = [device.get('vendor', 'Unknown') for device in devices]
    vendor_counts = Counter(vendors)

    # Create a pie chart for vendor distribution
    fig1, ax1 = plt.subplots()
    ax1.pie(vendor_counts.values(), labels=vendor_counts.keys(), autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures the pie is drawn as a circle.
    pie_chart_canvas = FigureCanvasTkAgg(fig1, master=chart_frame)
    pie_chart_canvas.draw()
    pie_chart_canvas.get_tk_widget().grid(row=0, column=0, padx=10, pady=10)

    # Create a bar chart for vendor counts
    fig2, ax2 = plt.subplots()
    ax2.bar(vendor_counts.keys(), vendor_counts.values())
    ax2.set_xlabel('Vendors')
    ax2.set_ylabel('Counts')
    ax2.set_title('Devices by Vendor')
    fig2.autofmt_xdate(rotation=45)
    bar_chart_canvas = FigureCanvasTkAgg(fig2, master=chart_frame)
    bar_chart_canvas.draw()
    bar_chart_canvas.get_tk_widget().grid(row=0, column=1, padx=10, pady=10)

def on_scan_button_click(entry, tree, advanced, status_label, count_label):
    global devices  # Declare devices as a global variable to use in the filter function
    ip_ranges = entry.get()
    conf.verb = 0  # Disable verbose mode in scapy
    status_label.config(text="Scanning...")  # Update status label to indicate scanning
    root.update_idletasks()  # Refresh the UI to show the updated status
    
    def run_scan():
        global devices
        devices = scan_network(ip_ranges, advanced)
        root.after(0, lambda: update_ui(devices, tree, advanced, status_label, count_label))  # Schedule the UI update in the main thread
    
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

def update_ui(devices, tree, advanced, status_label, count_label):
    if advanced:
        tree["displaycolumns"] = ("IP Address", "MAC Address", "Device Name", "Vendor")
    else:
        tree["displaycolumns"] = ("IP Address", "MAC Address")
    display_devices(devices, tree, advanced)
    count_label.config(text=f"Total Devices: {len(devices)}")
    status_label.config(text="Scan finished")  # Update status label to indicate scan is finished
    update_charts(devices)

def copy_to_clipboard(tree):
    selected_item = tree.focus()  # Get selected item
    if selected_item:
        item_values = tree.item(selected_item, "values")  # Get values of the selected item
        tree.clipboard_clear()
        if item_values:
            column_index = int(tree.identify_column(tree.winfo_pointerx() - tree.winfo_rootx()).replace('#', '')) - 1
            tree.clipboard_append(item_values[column_index])

def filter_tree(tree, query):
    for row in tree.get_children():
        tree.delete(row)
    for device in devices:
        device_info_str = ' '.join(str(value).lower() for value in device.values())
        if query.lower() in device_info_str:
            tree.insert("", "end", values=(device['ip'], device['mac'], device.get('name', 'Unknown'), device.get('vendor', 'Unknown')))

# Create the main window
root = tk.Tk()
root.title("Network Scanner")

# Create and place the widgets
frame = ttk.Frame(root, padding="10 10 20 20")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

label = ttk.Label(frame, text="Enter the IP ranges to scan (comma separated, e.g., 192.168.1.0/24, 192.168.2.0/24):")
label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

entry = ttk.Entry(frame, width=60)
entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

basic_scan_button = ttk.Button(frame, text="Basic Scan", command=lambda: on_scan_button_click(entry, tree, advanced=False, status_label=status_label, count_label=count_label))
basic_scan_button.grid(row=2, column=0, sticky=tk.E, padx=5)

advanced_scan_button = ttk.Button(frame, text="Advanced Scan", command=lambda: on_scan_button_click(entry, tree, advanced=True, status_label=status_label, count_label=count_label))
advanced_scan_button.grid(row=2, column=1, sticky=tk.W, padx=5)

columns = ("IP Address", "MAC Address", "Device Name", "Vendor")
tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
tree.grid(row=3, column=0, columnspan=2, pady=(10, 0), sticky=(tk.W, tk.E, tk.N, tk.S))

# Add scrollbars
scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
scrollbar_y.grid(row=3, column=2, sticky=(tk.N, tk.S))
scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
scrollbar_x.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

tree.heading("IP Address", text="IP Address")
tree.heading("MAC Address", text="MAC Address")
tree.heading("Device Name", text="Device Name")
tree.heading("Vendor", text="Vendor")
tree.column("IP Address", width=150)
tree.column("MAC Address", width=150)
tree.column("Device Name", width=150)
tree.column("Vendor", width=150)

# Adjust column widths for basic scan
tree["displaycolumns"] = ("IP Address", "MAC Address")

status_label = ttk.Label(frame, text="")
status_label.grid(row=5, column=0, columnspan=2, pady=(10, 0))

count_label = ttk.Label(frame, text="Total Devices: 0")
count_label.grid(row=6, column=0, columnspan=2, pady=(10, 0))

# Search box
search_label = ttk.Label(frame, text="Search:")
search_label.grid(row=7, column=0, sticky=tk.W, pady=(10, 0))
search_entry = ttk.Entry(frame, width=30)
search_entry.grid(row=7, column=1, sticky=(tk.W, tk.E), pady=(10, 0))

search_entry.bind("<KeyRelease>", lambda event: filter_tree(tree, search_entry.get()))

# Context menu for copying
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copy", command=lambda: copy_to_clipboard(tree))

def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

tree.bind("<Button-3>", show_context_menu)  # Bind right-click to show context menu

# Create chart frame
chart_frame = ttk.Frame(root, padding="10 10 20 20")
chart_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Make the window resizable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)
frame.rowconfigure(3, weight=1)

# Start the main evnt loop
root.mainloop()
