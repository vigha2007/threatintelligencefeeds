import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import RandomForestClassifier

# ─── LSTM Definition ─────────────────────────────────────────────────────────

class LSTMClassifier(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim,
                            num_layers=num_layers, batch_first=True, dropout=0.3)
        self.fc   = nn.Linear(hidden_dim, 1)
        self.sig  = nn.Sigmoid()

    def forward(self, x):
        # x shape: (batch, seq=1, features)
        out, _ = self.lstm(x)
        out     = self.fc(out[:, -1, :])
        return self.sig(out).squeeze()


# ─── Hybrid Model ─────────────────────────────────────────────────────────────

class HybridModel:
    """
    Combines Random Forest and LSTM predictions via soft voting.
    RF handles tabular patterns; LSTM captures sequential relationships.
    """

    def __init__(self, input_dim: int, epochs: int = 20, lr: float = 1e-3):
        self.rf        = RandomForestClassifier(n_estimators=100, random_state=42)
        self.lstm      = LSTMClassifier(input_dim)
        self.input_dim = input_dim
        self.epochs    = epochs
        self.lr        = lr
        self.device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.lstm.to(self.device)

    def _train_lstm(self, X: np.ndarray, y: np.ndarray):
        X_t = torch.tensor(X, dtype=torch.float32).unsqueeze(1).to(self.device)
        y_t = torch.tensor(y.values, dtype=torch.float32).to(self.device)

        loader    = DataLoader(TensorDataset(X_t, y_t), batch_size=64, shuffle=True)
        optimizer = torch.optim.Adam(self.lstm.parameters(), lr=self.lr)
        criterion = nn.BCELoss()

        self.lstm.train()
        for epoch in range(self.epochs):
            total_loss = 0
            for xb, yb in loader:
                optimizer.zero_grad()
                preds = self.lstm(xb)
                loss  = criterion(preds, yb)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            if (epoch + 1) % 5 == 0:
                print(f"  LSTM Epoch {epoch+1}/{self.epochs} — Loss: {total_loss:.4f}")

    def fit(self, X: np.ndarray, y):
        print("  Training Random Forest component...")
        self.rf.fit(X, y)
        print("  Training LSTM component...")
        self._train_lstm(X, y)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        # RF probabilities
        rf_prob = self.rf.predict_proba(X)[:, 1]

        # LSTM probabilities
        self.lstm.eval()
        with torch.no_grad():
            X_t      = torch.tensor(X, dtype=torch.float32).unsqueeze(1).to(self.device)
            lstm_prob = self.lstm(X_t).cpu().numpy()

        # Soft voting: average
        combined = (rf_prob + lstm_prob) / 2
        return np.column_stack([1 - combined, combined])

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)