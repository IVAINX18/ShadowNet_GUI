# Detector de Malware - Prototipo Antivirus

Interfaz gráfica para detectar malware en archivos ejecutables de Windows utilizando machine learning.

## Características

- Escaneo individual de archivos PE (executables .exe, .dll, .sys)
- Escaneo masivo de carpetas completas
- Detección en tiempo real usando modelo ONNX pre-entrenado
- Interfaz gráfica intuitiva con PyQt5
- Log de actividad en tiempo real
- Estadísticas de amenazas detectadas

## Requisitos

- Python 3.8 o superior
- Dependencias listadas en `requirements.txt`

## Instalación

1. Instalar las dependencias:

```bash
pip install -r requirements.txt
```

2. Asegurarse de que los archivos del modelo estén en la carpeta `models/`:
   - `best_model.onnx`
   - `scaler.pkl`

## Uso

Ejecutar la aplicación:

```bash
python run_detector.py
```

O directamente:

```bash
python gui/main_window.py
```

## Estructura del Proyecto

```
.
├── gui/
│   ├── detector.py           # Clase para cargar y ejecutar el modelo
│   ├── feature_extractor.py  # Extracción de características de archivos PE
│   ├── main_window.py        # Interfaz gráfica principal
│   └── styles.qss            # Estilos CSS para la interfaz
├── models/
│   ├── best_model.onnx       # Modelo entrenado
│   └── scaler.pkl            # Escalador de características
├── requirements.txt          # Dependencias del proyecto
└── run_detector.py           # Script principal para ejecutar la aplicación
```

## Funcionalidades de la Interfaz

### Botones Principales

- **Escanear Archivo**: Selecciona y escanea un archivo ejecutable individual
- **Escanear Carpeta**: Escanea todos los archivos .exe, .dll, .sys en una carpeta
- **Limpiar Resultados**: Borra los resultados anteriores y reinicia las estadísticas

### Visualización

- **Estado del Sistema**: Muestra si el modelo está cargado correctamente
- **Estadísticas**: Número de archivos escaneados y amenazas detectadas
- **Barra de Progreso**: Indica el progreso del escaneo actual
- **Resultados**: Lista detallada con archivos escaneados y su estado
  - ✓ Verde: Archivo seguro
  - ⚠️ Rojo: Malware detectado
  - ❌ Naranja: Error en el análisis
- **Log de Actividad**: Registro temporal de todas las acciones

## Nota Importante

Este es un prototipo educativo. Para uso en producción, se recomienda:
- Implementar cuarentena de archivos detectados
- Agregar base de datos de firmas de malware
- Incluir análisis heurístico adicional
- Integrar con sistemas de protección en tiempo real del SO
