import tensorflow as tf
import numpy as np


interpreter = tf.lite.Interpreter(model_path='lite_model_optimized_float16.tflite')
interpreter.allocate_tensors()

input_details = interpreter.get_input_details()

output_details = interpreter.get_output_details()

input_details[0]['shape']

input_shape = input_details[0]['shape']
X_test = np.array([15,2,4,365,5,8,0,1,3.189898095464287,0,1.0,3,31], dtype=np.uint32)

inp = np.expand_dims(X_test, axis=0)

inp = inp.astype(np.float32)

interpreter.set_tensor(input_details[0]['index'], inp)

interpreter.invoke()

pred = interpreter.get_tensor(output_details[0]['index'])[0][0]


print(pred)