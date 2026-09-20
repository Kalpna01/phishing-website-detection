from flask import Flask, request, render_template
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle

app = Flask(__name__)

# Load model & tokenizer
model = tf.keras.models.load_model('phishing_model.h5')
with open('tokenizer.pkl', 'rb') as f:
    tokenizer = pickle.load(f)

MAX_LEN = 150
SAFE_DOMAINS = ["google.com", "wikipedia.org", "github.com", "amazon.in", "youtube.com", "microsoft.com"]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url'].strip()
    url_clean = url.lower()
    
    # 1. Trusted Domain Check
    if any(domain in url_clean for domain in SAFE_DOMAINS):
        result = "✅ SAFE / LEGITIMATE"
        confidence = "100.00%"
        is_phishing = False
        return render_template('index.html', url=url, result=result, confidence=confidence, is_phishing=is_phishing)

    # 2. CNN + LSTM Model Prediction
    seq = tokenizer.texts_to_sequences([url_clean])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    
    prob = model.predict(padded, verbose=0)[0][0]
    
    if prob >= 0.65:
        result = "🚨 PHISHING / MALICIOUS WEBSITE DETECTED!"
        confidence = f"{prob * 100:.2f}%"
        is_phishing = True
    else:
        result = "✅ SAFE / LEGITIMATE WEBSITE"
        confidence = f"{(1 - prob) * 100:.2f}%"
        is_phishing = False

    return render_template('index.html', url=url, result=result, confidence=confidence, is_phishing=is_phishing)

if __name__ == '__main__':
    app.run(debug=True, port=5000)