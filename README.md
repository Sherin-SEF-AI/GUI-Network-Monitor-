# GUI-Network-Monitor-
Python application for network monitoring 
# Sci-Fi Network Monitor

Sci-Fi Network Monitor is a futuristic network monitoring application built with PyQt5 and Matplotlib. It captures and visualizes network packets in real-time, providing a sci-fi themed graphical representation of network traffic. Inspired by EtherApe, this application includes additional features like protocol filtering, customizable visualizations, and more.

## Features

- **Real-Time Packet Capture**: Capture and analyze network packets in real-time.
- **Sci-Fi Themed Visualization**: Visualize network data with a dark-themed, sci-fi styled graph.
- **Protocol Filtering**: Filter network packets by protocols such as TCP, UDP, and ICMP.
- **Customizable Visualization**: Change node and edge colors using a color picker dialog.
- **Node Statistics**: View detailed information about network nodes and their connections.
- **Export Data**: Export current visualizations to image files (PNG, PDF).
- **Log Viewer**: View logs of network activities.
- **Start, Stop, Pause, Resume Capture**: Manage the packet capture process with easy-to-use controls.

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Sherin-SEF-AI/GUI-Network-Monitor-.git
    cd GUI-Network-Monitor-
    ```

2. **Install Dependencies**:
    Make sure you have Python 3 installed. Then, install the required packages:
    ```bash
    pip install pyqt5 matplotlib scapy
    ```

## Usage

1. **Run the Application**:
    ```bash
    python networkmonitor.py
    ```

2. **Interact with the Application**:
    - **Start Capture**: Begin capturing network packets.
    - **Stop Capture**: Stop the packet capture process.
    - **Pause Capture**: Pause the ongoing packet capture.
    - **Resume Capture**: Resume the packet capture if paused.
    - **Protocol**: Select the network protocol to filter (TCP, UDP, ICMP).
    - **Node Info**: View statistics about network nodes.
    - **Export Data**: Save the current network visualization to a file.
    - **Customize Colors**: Change the colors of nodes and edges.
    - **View Logs**: Display a log of network activities.
    - **Help**: Get more information about using the application.

## Configuration

- **Protocols**: Select which protocol to filter using the dropdown menu.
- **Colors**: Customize node and edge colors using the color picker dialog.

## Troubleshooting

- **QStandardPaths Warning**: If you see a warning about `XDG_RUNTIME_DIR`, it is usually safe to ignore. This warning does not affect the functionality of the application.
- **Errors with Matplotlib**: Ensure all dependencies are installed correctly. Try updating Matplotlib or running the application in a different environment if you encounter issues.

## Contributing

Contributions are welcome! Please submit issues and pull requests to the [GitHub repository](https://github.com/Sherin-SEF-AI/GUI-Network-Monitor-).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact [your email address].
