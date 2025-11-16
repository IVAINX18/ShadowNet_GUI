import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QFileDialog,
                             QTextEdit, QProgressBar, QListWidget, QGroupBox,
                             QMessageBox, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QFont, QColor
from detector import MalwareDetector
from feature_extractor import FeatureExtractor
import time


class ScanThread(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(str, bool, str)
    finished_scan = pyqtSignal()

    def __init__(self, file_paths, detector, extractor):
        super().__init__()
        self.file_paths = file_paths
        self.detector = detector
        self.extractor = extractor

    def run(self):
        total = len(self.file_paths)
        for i, file_path in enumerate(self.file_paths):
            try:
                features = self.extractor.extract_features(file_path)

                if features is not None:
                    prediction = self.detector.predict(features)
                    is_malware = prediction == 1
                    status = "MALWARE DETECTADO" if is_malware else "SEGURO"
                    self.result.emit(file_path, is_malware, status)
                else:
                    self.result.emit(file_path, False, "ERROR - No se pudo analizar")

            except Exception as e:
                self.result.emit(file_path, False, f"ERROR: {str(e)}")

            progress_value = int((i + 1) / total * 100)
            self.progress.emit(progress_value)
            time.sleep(0.1)

        self.finished_scan.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.detector = None
        self.extractor = None
        self.scan_thread = None
        self.files_scanned = 0
        self.threats_found = 0

        self.init_ui()
        self.load_model()

    def init_ui(self):
        self.setWindowTitle("Detector de Malware - Prototipo Antivirus")
        self.setGeometry(100, 100, 900, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("DETECTOR DE MALWARE")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding: 15px;
                background-color: #ecf0f1;
                border-radius: 8px;
            }
        """)
        main_layout.addWidget(header)

        # Estado del sistema
        status_group = QGroupBox("Estado del Sistema")
        status_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        status_layout = QHBoxLayout()

        self.model_status = QLabel("Modelo: Cargando...")
        self.model_status.setStyleSheet("color: #f39c12; font-size: 13px;")
        status_layout.addWidget(self.model_status)

        self.stats_label = QLabel("Archivos escaneados: 0 | Amenazas: 0")
        self.stats_label.setAlignment(Qt.AlignRight)
        self.stats_label.setStyleSheet("color: #34495e; font-size: 13px;")
        status_layout.addWidget(self.stats_label)

        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)

        # Botones de acci�n
        button_layout = QHBoxLayout()

        self.scan_file_btn = QPushButton("Escanear Archivo")
        self.scan_file_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px 20px;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.scan_file_btn.clicked.connect(self.scan_file)
        button_layout.addWidget(self.scan_file_btn)

        self.scan_folder_btn = QPushButton("Escanear Carpeta")
        self.scan_folder_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px 20px;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.scan_folder_btn.clicked.connect(self.scan_folder)
        button_layout.addWidget(self.scan_folder_btn)

        self.clear_btn = QPushButton("Limpiar Resultados")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px 20px;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_btn)

        main_layout.addLayout(button_layout)

        # Barra de progreso
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        # Lista de resultados
        results_group = QGroupBox("Resultados del Escaneo")
        results_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        results_layout = QVBoxLayout()

        self.results_list = QListWidget()
        self.results_list.setStyleSheet("""
            QListWidget {
                background-color: #ffffff;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ecf0f1;
            }
        """)
        results_layout.addWidget(self.results_list)

        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group, 1)

        # Log de actividad
        log_group = QGroupBox("Log de Actividad")
        log_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(120)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #34495e;
                border-radius: 5px;
                padding: 8px;
                font-family: 'Courier New';
                font-size: 11px;
            }
        """)
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        self.log("Sistema iniciado. Esperando carga del modelo...")

    def load_model(self):
        try:
            self.log("Cargando modelo de detecci�n...")
            self.detector = MalwareDetector()
            self.extractor = FeatureExtractor()
            self.model_status.setText("Modelo:  Listo")
            self.model_status.setStyleSheet("color: #27ae60; font-size: 13px; font-weight: bold;")
            self.log("Modelo cargado exitosamente. Sistema listo para escanear.")
            self.scan_file_btn.setEnabled(True)
            self.scan_folder_btn.setEnabled(True)
        except Exception as e:
            self.model_status.setText("Modelo:  Error")
            self.model_status.setStyleSheet("color: #e74c3c; font-size: 13px; font-weight: bold;")
            self.log(f"ERROR al cargar el modelo: {str(e)}")
            self.scan_file_btn.setEnabled(False)
            self.scan_folder_btn.setEnabled(False)
            QMessageBox.critical(self, "Error", f"No se pudo cargar el modelo:\n{str(e)}")

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

    def scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo ejecutable",
            "",
            "Ejecutables (*.exe *.dll *.sys);;Todos los archivos (*.*)"
        )

        if file_path:
            self.start_scan([file_path])

    def scan_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")

        if folder_path:
            file_paths = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.endswith(('.exe', '.dll', '.sys')):
                        file_paths.append(os.path.join(root, file))

            if file_paths:
                self.log(f"Encontrados {len(file_paths)} archivos ejecutables en la carpeta")
                self.start_scan(file_paths)
            else:
                QMessageBox.information(self, "Informaci�n", "No se encontraron archivos ejecutables en la carpeta")

    def start_scan(self, file_paths):
        self.scan_file_btn.setEnabled(False)
        self.scan_folder_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.log(f"Iniciando escaneo de {len(file_paths)} archivo(s)...")

        self.scan_thread = ScanThread(file_paths, self.detector, self.extractor)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.result.connect(self.add_result)
        self.scan_thread.finished_scan.connect(self.scan_finished)
        self.scan_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def add_result(self, file_path, is_malware, status):
        self.files_scanned += 1
        if is_malware:
            self.threats_found += 1

        self.update_stats()

        item = QListWidgetItem()
        file_name = os.path.basename(file_path)

        if is_malware:
            item.setText(f"�  {file_name}\n    Estado: {status}\n    Ruta: {file_path}")
            item.setForeground(QColor("#e74c3c"))
            item.setFont(QFont("Arial", 10, QFont.Bold))
            self.log(f"�AMENAZA DETECTADA! {file_name}")
        elif "ERROR" in status:
            item.setText(f"L  {file_name}\n    Estado: {status}\n    Ruta: {file_path}")
            item.setForeground(QColor("#f39c12"))
        else:
            item.setText(f"  {file_name}\n    Estado: {status}\n    Ruta: {file_path}")
            item.setForeground(QColor("#27ae60"))

        self.results_list.addItem(item)

    def update_stats(self):
        self.stats_label.setText(f"Archivos escaneados: {self.files_scanned} | Amenazas: {self.threats_found}")

    def scan_finished(self):
        self.scan_file_btn.setEnabled(True)
        self.scan_folder_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        self.log("Escaneo completado.")

        if self.threats_found > 0:
            QMessageBox.warning(
                self,
                "Amenazas Detectadas",
                f"Se detectaron {self.threats_found} amenaza(s) potencial(es).\n\nRevise los resultados para m�s detalles."
            )
        else:
            QMessageBox.information(self, "Escaneo Completo", "No se detectaron amenazas.")

    def clear_results(self):
        self.results_list.clear()
        self.files_scanned = 0
        self.threats_found = 0
        self.update_stats()
        self.progress_bar.setValue(0)
        self.log("Resultados limpiados")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
