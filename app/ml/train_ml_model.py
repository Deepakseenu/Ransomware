import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# Define project paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
TRAINING_DATA_PATH = os.path.join(PROJECT_ROOT, 'training_data', 'training_data.csv')
MODEL_PATH = os.path.join(PROJECT_ROOT, 'app', 'models', 'ransomware_model.pkl')
ENCODER_PATH = os.path.join(PROJECT_ROOT, 'app', 'models', 'filetype_encoder.pkl')

# Ensure models folder exists
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# Load training data
df = pd.read_csv(TRAINING_DATA_PATH)

# Encode file types
le = LabelEncoder()
df['file_type_enc'] = le.fit_transform(df['file_type'])

# Define features and target
X = df[['file_type_enc', 'size_change', 'num_modifications']]
y = df['label']

# Train model
clf = RandomForestClassifier(random_state=42)
clf.fit(X, y)

# Save model and encoder
joblib.dump(clf, MODEL_PATH)
joblib.dump(le, ENCODER_PATH)

print(f"ML model trained and saved at {MODEL_PATH}")
print(f"Label encoder saved at {ENCODER_PATH}")
