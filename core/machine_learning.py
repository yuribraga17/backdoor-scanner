from sklearn.ensemble import RandomForestClassifier
import pandas as pd

def train_model(data_path):
    """
    Treina um modelo de machine learning para detectar backdoors.
    """
    data = pd.read_csv(data_path)
    X = data.drop("label", axis=1)
    y = data["label"]
    model = RandomForestClassifier()
    model.fit(X, y)
    return model

def predict(model, features):
    """
    Faz previsões com o modelo treinado.
    """
    return model.predict([features])