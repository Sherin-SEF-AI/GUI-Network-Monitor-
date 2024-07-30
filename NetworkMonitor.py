import sys
import threading
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from scapy.all import sniff, wrpcap, rdpcap
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QFileDialog, QComboBox, QLabel, QHBoxLayout, QMessageBox, QColorDialog
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QColor

class CaptureThread(QThread):
    packet_received = pyqtSignal(object)
    
    def __init__(self, protocol_filter=None, parent=None):
        super(CaptureThread, self).__init__(parent)
        self.protocol_filter = protocol_filter
        self.running = True
        self.paused = False

    def run(self):
        sniff(prn=self.process_packet, filter=self.protocol_filter, store=0)

    def process_packet(self, packet):
        if self.running and not self.paused:
            self.packet_received.emit(packet)

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Sci-Fi Network Monitor")
        self.setGeometry(100, 100, 1200, 800)
        
        self.init_ui()
        
        self.capture_thread = None
        self.graph = nx.Graph()
        self.pos = {}
        self.packet_counts = {}
        self.node_color = 'cyan'
        self.edge_color = 'magenta'

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        self.text_edit = QTextEdit()
        layout.addWidget(self.text_edit)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        button_layout.addWidget(self.stop_button)
        
        self.pause_button = QPushButton("Pause Capture")
        self.pause_button.clicked.connect(self.pause_capture)
        button_layout.addWidget(self.pause_button)
        
        self.resume_button = QPushButton("Resume Capture")
        self.resume_button.clicked.connect(self.resume_capture)
        button_layout.addWidget(self.resume_button)
        
        self.protocol_label = QLabel("Protocol:")
        button_layout.addWidget(self.protocol_label)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("")
        self.protocol_combo.addItem("tcp")
        self.protocol_combo.addItem("udp")
        self.protocol_combo.addItem("icmp")
        button_layout.addWidget(self.protocol_combo)
        
        self.node_info_button = QPushButton("Node Info")
        self.node_info_button.clicked.connect(self.show_node_info)
        button_layout.addWidget(self.node_info_button)
        
        self.export_button = QPushButton("Export Data")
        self.export_button.clicked.connect(self.export_data)
        button_layout.addWidget(self.export_button)
        
        self.color_button = QPushButton("Customize Colors")
        self.color_button.clicked.connect(self.customize_colors)
        button_layout.addWidget(self.color_button)
        
        self.log_view_button = QPushButton("View Logs")
        self.log_view_button.clicked.connect(self.view_logs)
        button_layout.addWidget(self.log_view_button)
        
        self.help_button = QPushButton("Help")
        self.help_button.clicked.connect(self.show_help)
        button_layout.addWidget(self.help_button)
        
        layout.addLayout(button_layout)
        
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)
        
        self.ax.set_facecolor('black')
        self.fig.patch.set_facecolor('black')

    def start_capture(self):
        protocol = self.protocol_combo.currentText()
        self.capture_thread = CaptureThread(protocol_filter=f"proto {protocol}" if protocol else None)
        self.capture_thread.packet_received.connect(self.handle_packet)
        self.capture_thread.start()
        self.text_edit.append("Capture started.")
        
    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.text_edit.append("Capture stopped.")
        
    def pause_capture(self):
        if self.capture_thread:
            self.capture_thread.pause()
            self.text_edit.append("Capture paused.")
        
    def resume_capture(self):
        if self.capture_thread:
            self.capture_thread.resume()
            self.text_edit.append("Capture resumed.")
        
    def handle_packet(self, packet):
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            self.update_graph(src_ip, dst_ip)
            self.update_display(f"{src_ip} -> {dst_ip}")
            self.update_visualization()
        
    def update_display(self, packet_info):
        self.text_edit.append(packet_info)

    def update_graph(self, src_ip, dst_ip):
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip)
        if not self.graph.has_node(dst_ip):
            self.graph.add_node(dst_ip)
        if not self.graph.has_edge(src_ip, dst_ip):
            self.graph.add_edge(src_ip, dst_ip)

    def update_visualization(self):
        try:
            self.ax.clear()
            self.pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
            nx.draw(
                self.graph, 
                pos=self.pos, 
                with_labels=True, 
                node_size=300, 
                node_color=self.node_color, 
                edge_color=self.edge_color, 
                alpha=0.6, 
                linewidths=2, 
                font_size=10, 
                font_color='white'
            )
            self.ax.set_facecolor('black')
            self.fig.patch.set_facecolor('black')
            self.canvas.draw()
        except Exception as e:
            print(f"Error updating visualization: {e}")

    def show_node_info(self):
        info = "\n".join(f"{node}: {self.graph.degree(node)} connections" for node in self.graph.nodes())
        QMessageBox.information(self, "Node Information", info)

    def export_data(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Data", "", "Image files (*.png *.pdf)")
        if file_path:
            self.fig.savefig(file_path)
            self.text_edit.append(f"Data exported to {file_path}.")

    def customize_colors(self):
        node_color = QColorDialog.getColor()
        if node_color.isValid():
            self.node_color = node_color.name()
        edge_color = QColorDialog.getColor()
        if edge_color.isValid():
            self.edge_color = edge_color.name()
        self.update_visualization()

    def view_logs(self):
        log_text = "\n".join(f"{node}: {self.graph.degree(node)} connections" for node in self.graph.nodes())
        QMessageBox.information(self, "Network Logs", log_text)

    def show_help(self):
        help_text = (
            "Sci-Fi Network Monitor Help\n\n"
            "1. Start Capture: Begin capturing network packets.\n"
            "2. Stop Capture: Stop capturing network packets.\n"
            "3. Pause Capture: Pause the packet capture.\n"
            "4. Resume Capture: Resume the packet capture.\n"
            "5. Protocol: Filter packets by protocol.\n"
            "6. Node Info: Show information about network nodes.\n"
            "7. Export Data: Export current visualization to an image file.\n"
            "8. Customize Colors: Change node and edge colors.\n"
            "9. View Logs: View detailed network logs.\n"
            "10. Help: Show this help message."
        )
        QMessageBox.information(self, "Help", help_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitor()
    window.show()
    sys.exit(app.exec_())

