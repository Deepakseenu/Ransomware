import pandas as pd
import os

# Define project paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
TRAINING_DATA_PATH = os.path.join(PROJECT_ROOT, 'training_data', 'training_data.csv')

# Create training data
data = [
    {'file_type': '.txt', 'size_change': 0, 'num_modifications': 1, 'label': 'benign'},
    {'file_type': '.docx', 'size_change': 1024, 'num_modifications': 10, 'label': 'ransomware'},
    {'file_type': '.pdf', 'size_change': 0, 'num_modifications': 1, 'label': 'benign'},
    {'file_type': '.xlsx', 'size_change': 2048, 'num_modifications': 15, 'label': 'ransomware'},
]

df = pd.DataFrame(data)

# Ensure the training_data folder exists
os.makedirs(os.path.dirname(TRAINING_DATA_PATH), exist_ok=True)

# Save CSV
df.to_csv(TRAINING_DATA_PATH, index=False)
print(f"Training data created at {TRAINING_DATA_PATH}")
