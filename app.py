import sys
import socket
import threading
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime
from PyQt6 import QtWidgets, QtCore

# ----------------------------
# Helper for DLT writing
# ----------------------------
class DLTWriter:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, "wb")

    def write_message(self, timestamp: datetime, ecu: str, level: str, content: str):
        # Minimal DLT header simulation
        # AUTOSAR DLT standard: simplified header (big-endian)
        try:
            ts_str = timestamp.isoformat().encode('utf-8')
            ecu_bytes = ecu.encode('utf-8')[:8].ljust(8, b'\0')
            level_bytes = level.encode('utf-8')[:8].ljust(8, b'\0')
            content_bytes = content.encode('utf-8', errors='replace')
            length = len(ts_str) + len(ecu_bytes) + len(level_bytes) + len(content_bytes)
            if length > 0xFFFFFFFF:
                length = 0xFFFFFFFF  # prevent overflow
            self.file.write(length.to_bytes(4, 'big'))
            self.file.write(ts_str + ecu_bytes + level_bytes + content_bytes)
        except Exception as e:
            print("DLT write error:", e)

    def close(self):
        self.file.close()


# ----------------------------
# Live Log Window
# ----------------------------
class LogWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Live Log")
        self.resize(900, 600)
        layout = QtWidgets.QVBoxLayout(self)
        self.log_output = QtWidgets.QPlainTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

    def append_lines(self, lines):
        self.log_output.appendPlainText("\n".join(lines))


# ----------------------------
# Main Application Window
# ----------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S2DB + DLT Capture Tool")
        self.resize(800, 600)

        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QtWidgets.QVBoxLayout(self.central_widget)

        # Menu
        self.menu = self.menuBar()
        file_menu = self.menu.addMenu("File")
        open_cfg_action = QtWidgets.QAction("Open Config...", self)
        open_cfg_action.triggered.connect(self.open_config)
        file_menu.addAction(open_cfg_action)

        open_log_action = QtWidgets.QAction("Open Log File...", self)
        open_log_action.triggered.connect(self.open_log_file)
        file_menu.addAction(open_log_action)

        save_dlt_action = QtWidgets.QAction("Save DLT...", self)
        save_dlt_action.triggered.connect(self.save_dlt)
        file_menu.addAction(save_dlt_action)

        search_action = QtWidgets.QAction("Search...", self)
        search_action.triggered.connect(self.search_text)
        file_menu.addAction(search_action)

        # Configuration path
        self.cfg_label = QtWidgets.QLabel("Config File:")
        layout.addWidget(self.cfg_label)
        self.cfg_path = QtWidgets.QLineEdit()
        layout.addWidget(self.cfg_path)
        self.browse_cfg_btn = QtWidgets.QPushButton("Browse Config")
        self.browse_cfg_btn.clicked.connect(self.open_config)
        layout.addWidget(self.browse_cfg_btn)

        # Host/Port
        self.host_input = QtWidgets.QLineEdit("::1")
        self.port_input = QtWidgets.QLineEdit("12345")
        layout.addWidget(QtWidgets.QLabel("ECU IPv6 Host:"))
        layout.addWidget(self.host_input)
        layout.addWidget(QtWidgets.QLabel("Port:"))
        layout.addWidget(self.port_input)

        # Start/Stop capture
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        layout.addWidget(self.start_btn)

        # Log window
        self.log_window = LogWindow()
        self.log_window.show()

        # State
        self.capture_thread = None
        self.running = False
        self.signals_dict = {}
        self.log_buffer = []
        self.dlt_writer = None
        self.local_codebooks = []

    # ----------------------------
    # Config parsing
    # ----------------------------
    def open_config(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Config File", "", "XML Config (*.xml)"
        )
        if not file_name:
            return
        self.cfg_path.setText(file_name)
        try:
            tree = ET.parse(file_name)
            root = tree.getroot()
            self.local_codebooks.clear()
            for cfg in root.findall(".//LocalCodebookConfig"):
                for codebook in cfg.findall(".//LocalCodebook"):
                    path = codebook.text.strip()
                    if Path(path).exists():
                        self.local_codebooks.append(path)
            QtWidgets.QMessageBox.information(self, "Info", f"Loaded {len(self.local_codebooks)} codebooks.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to parse config: {e}")

    # ----------------------------
    # Log file open (offline)
    # ----------------------------
    def open_log_file(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Open Log File", "", "S2DB Files (*.s2db);;All Files (*)"
        )
        if not file_name:
            return
        try:
            with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
                self.append_log_batch(lines)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to open log file: {e}")

    # ----------------------------
    # Log batch append
    # ----------------------------
    def append_log_batch(self, lines):
        self.log_buffer.extend(lines)
        self.log_window.append_lines(lines)
        if self.dlt_writer:
            ts = datetime.now()
            for line in lines:
                self.dlt_writer.write_message(ts, "ECU", "Info", line)

    # ----------------------------
    # Save DLT
    # ----------------------------
    def save_dlt(self):
        if not self.log_buffer:
            QtWidgets.QMessageBox.warning(self, "Warning", "No log to save")
            return
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save DLT File", "", "DLT Files (*.dlt)"
        )
        if not file_name:
            return
        try:
            self.dlt_writer = DLTWriter(file_name)
            ts = datetime.now()
            for line in self.log_buffer:
                self.dlt_writer.write_message(ts, "ECU", "Info", line)
            self.dlt_writer.close()
            QtWidgets.QMessageBox.information(self, "Info", f"Saved {len(self.log_buffer)} lines to DLT")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to save DLT: {e}")

    # ----------------------------
    # Search
    # ----------------------------
    def search_text(self):
        text, ok = QtWidgets.QInputDialog.getText(self, "Search Logs", "Enter keyword:")
        if ok and text:
            matches = [line for line in self.log_buffer if text in line]
            QtWidgets.QMessageBox.information(self, "Search Results", f"Found {len(matches)} lines.")

    # ----------------------------
    # Capture loop
    # ----------------------------
    def start_capture(self):
        if not self.running:
            host = self.host_input.text()
            try:
                port = int(self.port_input.text())
            except ValueError:
                QtWidgets.QMessageBox.warning(self, "Error", "Invalid port")
                return
            self.running = True
            self.start_btn.setText("Stop Capture")
            self.capture_thread = threading.Thread(target=self.capture_loop, args=(host, port), daemon=True)
            self.capture_thread.start()
        else:
            self.running = False
            self.start_btn.setText("Start Capture")

    def capture_loop(self, host, port):
        self.append_log_batch([f"Connecting to {host}:{port} ..."])
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.connect((host, port, 0, 0))
                self.append_log_batch(["Connected. Receiving logs..."])
                while self.running:
                    data = s.recv(4096)
                    if not data:
                        break
                    try:
                        text = data.decode("utf-8", errors="ignore")
                    except Exception:
                        text = str(data)
                    lines = text.splitlines()
                    self.append_log_batch(lines)
        except Exception as e:
            self.append_log_batch([f"Error: {e}"])
        finally:
            self.running = False
            self.start_btn.setText("Start Capture")


# ----------------------------
# Main
# ----------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
