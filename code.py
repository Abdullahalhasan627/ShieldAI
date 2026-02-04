import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
import numpy as np

# بيانات تدريب تجريبية (لإثبات الفكرة)
X_dummy = np.random.rand(1000, 20).astype(np.float32)
y_dummy = np.random.randint(0, 2, 1000)

model = lgb.LGBMClassifier()
model.fit(X_dummy, y_dummy)

initial_type = [('float_input', FloatTensorType([None, 20]))]

onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type)

with open("model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("✅ Model exported to model.onnx")
