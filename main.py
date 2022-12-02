import sys
import subprocess

# implement pip as a subprocess:
subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])

import json
from flask import Flask
from flask_cors import CORS
import feature_extractions
import tensorflow as tf
import numpy as np

interpreter = tf.lite.Interpreter(model_path='lite_model_optimized_float16.tflite')
interpreter.allocate_tensors()
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()
input_details[0]['shape']
input_shape = input_details[0]['shape']


# if __name__ == '__main__':
#     start('rgu.ac.uk')

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return json.dumps({'Malicious_status': 'Yes'})


@app.route('/test_url/<string:test_url>', methods=['GET'])
def get(test_url):
    test_url = test_url.replace("_**_", "/")
    print(test_url)
    test_url = test_url.replace("https://www.","").replace("http://www.","").replace("https://","").replace("http://","")
    domain = test_url.split("/")[0]
    features_array = feature_extractions.extract_features(domain)
    print(features_array)
    X_test = np.array(features_array, dtype=np.uint32)

    inp = np.expand_dims(X_test, axis=0)

    inp = inp.astype(np.float32)

    interpreter.set_tensor(input_details[0]['index'], inp)

    interpreter.invoke()

    malicious_status = int(interpreter.get_tensor(output_details[0]['index'])[0][0])

    print("malicious_status: "+str(malicious_status))
    return json.dumps({'mal_status': malicious_status})


app.run()
