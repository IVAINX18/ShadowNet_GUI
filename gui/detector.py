import numpy as np
import onnxruntime as ort
import pickle
import os

class MalwareDetector:
    def __init__(self):
        base_path = os.path.dirname(os.path.dirname(__file__))
        model_path = os.path.join(base_path, "models", "best_model.onnx")
        scaler_path = os.path.join(base_path, "models", "scaler.pkl")

        # Cargar scaler
        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        # Cargar modelo ONNX
        self.session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])

        # Inputs y outputs ONNX
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name

    def predict(self, features: np.ndarray) -> int:
        """
        features: np.array shape (n_features,)
        return: 0 = benigno, 1 = malware
        """

        # Ajustar forma para batch
        features = features.reshape(1, -1)

        # Escalar
        features_scaled = self.scaler.transform(features).astype(np.float32)

        # ONNX inference
        result = self.session.run([self.output_name], {self.input_name: features_scaled})[0]

        # Si la red retorna logits, tomamos argmax
        pred = int(np.argmax(result, axis=1)[0])

        return pred
