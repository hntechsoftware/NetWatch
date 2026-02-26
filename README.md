# NetWatch
### Minimalistic network analysis tool using Scapy and NiceGUI.

NetWatch is a basic packet sniffing program that captures and records network traffic (Scapy) and displays it using a web browser (NiceGUI).
Current features include:
- Constant refreshing to show scanned packets
- Parsing and displaying source and destination IP
- Utilise the Ipify API to show the real-world location of the IP
- Display raw hexadecimal data captured from the packet
- Displaying packet info such as protocol, timestamp, and others

Work-in-progress features include:
- Sorting by time and location
- Deciphering the operating system sending the packets
- Using a dict to store IP locations (save on API calls)
- Attempting decode of packet info

DISCLAIMER: This tool is intended for cybersecurity and research purposes. It is not capable of any real harmful activity and is essentially a boilerplate for a more advanced packet sniffer (hence why I refer to it as a "network analysis tool" and not "packet sniffer"). I obviously do not endorse using NetWatch for any harmful purpose.
