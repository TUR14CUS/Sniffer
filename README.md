# Sniffer.py

## Overview

The `sniffer.py` script is a network packet sniffer implemented in Python using Scapy, a powerful packet manipulation library. This script is designed to capture and analyze network traffic, specifically focusing on HTTP requests. It can identify and print out URLs being accessed and potential username/password combinations transmitted over the network.

## Prerequisites

Before running the script, ensure you have the necessary dependencies installed. You can install them using the following command:

```bash
pip install scapy
```

## Usage

To use the script, simply execute it with the desired network interface as an argument. For example:

```bash
python sniffer.py eth0
```

## Functionality

### 1. HTTP Requests

The script monitors HTTP requests and prints out the URLs being accessed. If an HTTP request is detected, the script displays the corresponding URL.

```python
[+] HTTP Request >> http://www.example.com/login
```

### 2. Username/Password Detection

The script searches for potential username/password combinations in the payload of packets. If any keywords related to login credentials are found, the script prints the identified information.

```python
[+] Possible username/password > user=admin&pass=admin123
```

## Error Handling

The script includes basic error handling to catch and display any exceptions that may occur during packet sniffing.

```python
An error occurred while sniffing packets: <error_message>
```

## Disclaimer

This script is intended for educational and testing purposes only. Unauthorized interception of network traffic may violate privacy and legal regulations. Use this script responsibly and only on networks you have explicit permission to monitor.

## Author

- **TUR14CUS** - [GitHub](https://github.com/TUR14CUS)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
