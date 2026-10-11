from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

urls = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://github.com",
    "https://www.apple.com",
    "https://www.python.org",
    "https://www.linkedin.com",

    "http://login-verify-account.xyz",
    "http://secure-bank-login.tk",
    "http://update-password-account.ml",
    "http://verify-bank-account.ga",
    "http://confirm-login-security.cf",
    "http://paypal-login-verify.xyz",
    "http://account-password-update.tk",
    "http://secure-login-bank.ml"
]

labels = [
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1
]

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5)
)

X = vectorizer.fit_transform(urls)

model = LogisticRegression()
model.fit(X, labels)

joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "url_vectorizer.pkl")

print("AI/ML model trained successfully!")
print("Model saved as phishing_model.pkl")
print("Vectorizer saved as url_vectorizer.pkl")

