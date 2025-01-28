import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder

# Load dataset
data = pd.read_csv('ddos.csv')

# Debugging: Print the column names to verify
print("Dataset columns:", data.columns)

# Preprocess data
columns_to_drop = ['tcp.dstport', 'ip.proto', 'tcp.seq', 'tcp.ack', 'frame.time']
columns_to_drop = [col for col in columns_to_drop if col in data.columns]  # Drop only existing columns
data = data.drop(columns=columns_to_drop)

# Encode non-numeric columns
non_numeric_cols = ['ip.src', 'ip.dst']  # Columns to encode
for col in non_numeric_cols:
    if col in data.columns:
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col])

# Ensure correct label column name
data['Label'] = data['Label'].apply(lambda x: 'Benign' if x == 'Benign' else 'DDoS')

# Split dataset into features and labels
X = data.drop(columns=['Label'])
y = data['Label']

# Debugging: Check feature and label shapes
print("Feature shape:", X.shape)
print("Label shape:", y.shape)

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))
