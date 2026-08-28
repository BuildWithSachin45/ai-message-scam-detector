import os
import glob
import pickle
import numpy as np
import pandas as pd
from PIL import Image, ImageStat
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ==========================================================
# 1. TRAIN NLP SCAM DETECTION MODEL (SMS & TEXT)
# ==========================================================
print("--> Training NLP Scam Detection Model...")

# Locate spam dataset
spam_path = os.path.join('datasets', 'spam.csv')
if not os.path.exists(spam_path):
    spam_path = os.path.join('datasets', 'sms_spam_collection.csv')

df_spam = pd.read_csv(spam_path, encoding='latin-1')
# Standardize columns (v1: label, v2: message)
df_spam = df_spam.iloc[:, [0, 1]]
df_spam.columns = ['label', 'message']
df_spam['label_num'] = df_spam['label'].map({'ham': 0, 'spam': 1})
df_spam = df_spam.dropna(subset=['message', 'label_num'])

X_train_txt, X_test_txt, y_train_txt, y_test_txt = train_test_split(
    df_spam['message'], df_spam['label_num'], test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
X_train_vec = vectorizer.fit_transform(X_train_txt)
X_test_vec = vectorizer.transform(X_test_txt)

text_model = MultinomialNB(alpha=0.1)
text_model.fit(X_train_vec, y_train_txt)

text_preds = text_model.predict(X_test_vec)
text_acc = accuracy_score(y_test_txt, text_preds)
print(f"    Text Model Accuracy: {text_acc * 100:.2f}%")

with open('scam_model.pkl', 'wb') as f:
    pickle.dump(text_model, f)

with open('vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("    Saved: scam_model.pkl, vectorizer.pkl\n")


# ==========================================================
# 2. TRAIN SYNTHETIC / FAKE IMAGE CLASSIFIER (LIGHTWEIGHT)
# ==========================================================
def extract_image_features(img_path):
    """
    Extracts statistical & artifact features (variance, mean, std, entropy)
    without requiring heavy deep learning frameworks.
    """
    try:
        with Image.open(img_path) as img:
            img_gray = img.convert('L').resize((64, 64))
            stat = ImageStat.Stat(img_gray)
            
            # Pixel statistics
            mean_val = stat.mean[0]
            var_val = stat.var[0]
            std_val = stat.stddev[0]
            
            # Simple histogram entropy proxy
            hist = img_gray.histogram()
            hist_sum = sum(hist)
            probs = [h / hist_sum for h in hist if h > 0]
            entropy = -sum(p * np.log2(p) for p in probs)
            
            return [mean_val, var_val, std_val, entropy]
    except Exception:
        return None

def load_image_folder(folder_path, label, max_samples=3000):
    features = []
    labels = []
    # Search all common image formats
    image_files = []
    for ext in ('*.png', '*.jpg', '*.jpeg', '*.webp'):
        image_files.extend(glob.glob(os.path.join(folder_path, ext)))
        image_files.extend(glob.glob(os.path.join(folder_path, ext.upper())))
    
    # Cap samples for quick training while preserving accuracy
    image_files = image_files[:max_samples]
    
    for fpath in image_files:
        feats = extract_image_features(fpath)
        if feats is not None:
            features.append(feats)
            labels.append(label)
            
    return features, labels

train_fake_dir = os.path.join('datasets', 'train', 'FAKE')
train_real_dir = os.path.join('datasets', 'train', 'REAL')
test_fake_dir = os.path.join('datasets', 'test', 'FAKE')
test_real_dir = os.path.join('datasets', 'test', 'REAL')

if os.path.exists(train_fake_dir) and os.path.exists(train_real_dir):
    print("--> Training Synthetic/Fake Image Classifier...")
    
    X_train_img, y_train_img = [], []
    X_test_img, y_test_img = [], []
    
    # FAKE = 1, REAL = 0
    fake_feats, fake_labels = load_image_folder(train_fake_dir, 1)
    real_feats, real_labels = load_image_folder(train_real_dir, 0)
    X_train_img.extend(fake_feats + real_feats)
    y_train_img.extend(fake_labels + real_labels)
    
    if os.path.exists(test_fake_dir) and os.path.exists(test_real_dir):
        t_fake_feats, t_fake_labels = load_image_folder(test_fake_dir, 1, max_samples=1000)
        t_real_feats, t_real_labels = load_image_folder(test_real_dir, 0, max_samples=1000)
        X_test_img.extend(t_fake_feats + t_real_feats)
        y_test_img.extend(t_fake_labels + t_real_labels)
    else:
        X_train_img, X_test_img, y_train_img, y_test_img = train_test_split(
            X_train_img, y_train_img, test_size=0.2, random_state=42
        )
        
    img_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    img_model.fit(X_train_img, y_train_img)
    
    img_preds = img_model.predict(X_test_img)
    img_acc = accuracy_score(y_test_img, img_preds)
    print(f"    Image Model Accuracy: {img_acc * 100:.2f}%")
    
    with open('image_model.pkl', 'wb') as f:
        pickle.dump(img_model, f)
    print("    Saved: image_model.pkl\n")
else:
    print("[!] Image train folders not detected in 'datasets/train/'. Skipping image model training.")

print("All models trained and ready!")