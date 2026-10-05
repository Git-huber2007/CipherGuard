"""A small 1D convolutional network, implemented directly on NumPy.

The deployment target is a passive sensor on an isolated backbone segment, where
shipping a multi-hundred-megabyte deep-learning runtime is a procurement and
attack-surface problem rather than a convenience. The network is small enough
(about 6k parameters) that forward and backward passes in NumPy are fast, and
the saved model is a single .npz of a few tens of kilobytes.

Architecture, over the 64-point distribution profile from features.signal():

    conv(1 -> 16, k=5) - ReLU - maxpool2
    conv(16 -> 32, k=3) - ReLU - maxpool2
    global average pool
    dense(32 -> 64) - ReLU
    dense(64 -> classes) - softmax

Convolution is the right inductive bias here: the modulo profiles are periodic
signals whose informative structure is a local peak at a particular residue, and
that peak means the same thing wherever the padding alignment puts it.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def _he(shape: tuple[int, ...], fan_in: int, rng: np.random.Generator) -> np.ndarray:
    return rng.normal(0.0, np.sqrt(2.0 / fan_in), size=shape)


class Conv1D:
    def __init__(self, cin: int, cout: int, k: int, rng: np.random.Generator):
        self.k = k
        self.pad = k // 2
        self.W = _he((cout, cin, k), cin * k, rng)
        self.b = np.zeros(cout)
        self._cols: np.ndarray | None = None

    def forward(self, x: np.ndarray) -> np.ndarray:
        n, cin, length = x.shape
        xp = np.pad(x, ((0, 0), (0, 0), (self.pad, self.pad)))
        cols = np.stack([xp[:, :, i : i + length] for i in range(self.k)], axis=-1)
        self._cols = cols
        return np.einsum("nclk,ock->nol", cols, self.W, optimize=True) + self.b[None, :, None]

    def backward(self, dout: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        assert self._cols is not None
        cols = self._cols
        dW = np.einsum("nol,nclk->ock", dout, cols, optimize=True)
        db = dout.sum(axis=(0, 2))
        dcols = np.einsum("nol,ock->nclk", dout, self.W, optimize=True)

        n, cin, length, _ = dcols.shape
        dxp = np.zeros((n, cin, length + 2 * self.pad))
        for i in range(self.k):
            dxp[:, :, i : i + length] += dcols[:, :, :, i]
        dx = dxp[:, :, self.pad : self.pad + length] if self.pad else dxp
        return dx, dW, db


class MaxPool1D:
    def __init__(self, size: int = 2):
        self.size = size
        self._mask: np.ndarray | None = None
        self._shape: tuple[int, ...] | None = None

    def forward(self, x: np.ndarray) -> np.ndarray:
        n, c, length = x.shape
        trimmed = length - (length % self.size)
        x = x[:, :, :trimmed]
        reshaped = x.reshape(n, c, trimmed // self.size, self.size)
        idx = reshaped.argmax(axis=-1)
        self._mask = idx
        self._shape = (n, c, trimmed)
        return reshaped.max(axis=-1)

    def backward(self, dout: np.ndarray) -> np.ndarray:
        assert self._mask is not None and self._shape is not None
        n, c, trimmed = self._shape
        dx = np.zeros((n, c, trimmed // self.size, self.size))
        i, j, k = np.indices(self._mask.shape)
        dx[i, j, k, self._mask] = dout
        return dx.reshape(n, c, trimmed)


class Dense:
    def __init__(self, nin: int, nout: int, rng: np.random.Generator):
        self.W = _he((nin, nout), nin, rng)
        self.b = np.zeros(nout)
        self._x: np.ndarray | None = None

    def forward(self, x: np.ndarray) -> np.ndarray:
        self._x = x
        return x @ self.W + self.b

    def backward(self, dout: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        assert self._x is not None
        return dout @ self.W.T, self._x.T @ dout, dout.sum(axis=0)


def softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


class Adam:
    def __init__(self, params: list[np.ndarray], lr: float = 3e-3):
        self.lr = lr
        self.m = [np.zeros_like(p) for p in params]
        self.v = [np.zeros_like(p) for p in params]
        self.t = 0

    def step(self, params: list[np.ndarray], grads: list[np.ndarray]) -> None:
        self.t += 1
        b1, b2, eps = 0.9, 0.999, 1e-8
        for i, (p, g) in enumerate(zip(params, grads)):
            self.m[i] = b1 * self.m[i] + (1 - b1) * g
            self.v[i] = b2 * self.v[i] + (1 - b2) * (g * g)
            mhat = self.m[i] / (1 - b1**self.t)
            vhat = self.v[i] / (1 - b2**self.t)
            p -= self.lr * mhat / (np.sqrt(vhat) + eps)


class EspCNN:
    """1D-CNN over the ESP distribution profile."""

    def __init__(self, n_classes: int, signal_len: int = 64, seed: int = 1337):
        rng = np.random.default_rng(seed)
        self.conv1 = Conv1D(1, 16, 5, rng)
        self.pool1 = MaxPool1D(2)
        self.conv2 = Conv1D(16, 32, 3, rng)
        self.pool2 = MaxPool1D(2)
        self.fc1 = Dense(32, 64, rng)
        self.fc2 = Dense(64, n_classes, rng)
        self.n_classes = n_classes
        self.signal_len = signal_len
        self._cache: dict = {}

    # -- parameter plumbing -------------------------------------------------

    def _params(self) -> list[np.ndarray]:
        return [
            self.conv1.W,
            self.conv1.b,
            self.conv2.W,
            self.conv2.b,
            self.fc1.W,
            self.fc1.b,
            self.fc2.W,
            self.fc2.b,
        ]

    # -- forward / backward -------------------------------------------------

    def forward(self, x: np.ndarray) -> np.ndarray:
        x = x.reshape(x.shape[0], 1, -1)
        a1 = self.conv1.forward(x)
        r1 = np.maximum(a1, 0)
        p1 = self.pool1.forward(r1)
        a2 = self.conv2.forward(p1)
        r2 = np.maximum(a2, 0)
        p2 = self.pool2.forward(r2)
        gap = p2.mean(axis=2)
        h = self.fc1.forward(gap)
        rh = np.maximum(h, 0)
        logits = self.fc2.forward(rh)
        self._cache = dict(a1=a1, a2=a2, p2shape=p2.shape, h=h)
        return logits

    def backward(self, dlogits: np.ndarray) -> list[np.ndarray]:
        c = self._cache
        drh, dW2, db2 = self.fc2.backward(dlogits)
        dh = drh * (c["h"] > 0)
        dgap, dW1, db1 = self.fc1.backward(dh)

        n, ch, length = c["p2shape"]
        dp2 = np.repeat(dgap[:, :, None], length, axis=2) / length
        dr2 = self.pool2.backward(dp2)
        da2 = dr2 * (c["a2"] > 0)
        dp1, dcW2, dcb2 = self.conv2.backward(da2)
        dr1 = self.pool1.backward(dp1)
        da1 = dr1 * (c["a1"] > 0)
        _, dcW1, dcb1 = self.conv1.backward(da1)
        return [dcW1, dcb1, dcW2, dcb2, dW1, db1, dW2, db2]

    # -- training -----------------------------------------------------------

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 60,
        batch_size: int = 32,
        lr: float = 3e-3,
        seed: int = 0,
        verbose: bool = False,
    ) -> list[float]:
        rng = np.random.default_rng(seed)
        params = self._params()
        opt = Adam(params, lr=lr)
        history: list[float] = []
        n = X.shape[0]

        for epoch in range(epochs):
            order = rng.permutation(n)
            total = 0.0
            for start in range(0, n, batch_size):
                idx = order[start : start + batch_size]
                xb, yb = X[idx], y[idx]
                logits = self.forward(xb)
                probs = softmax(logits)
                loss = -np.log(np.clip(probs[np.arange(len(yb)), yb], 1e-12, None)).mean()
                total += loss * len(yb)

                dlogits = probs.copy()
                dlogits[np.arange(len(yb)), yb] -= 1.0
                dlogits /= len(yb)
                grads = self.backward(dlogits)
                opt.step(params, grads)

            history.append(total / n)
            if verbose and (epoch % 10 == 0 or epoch == epochs - 1):
                print(f"  epoch {epoch:3d}  loss {history[-1]:.4f}")
        return history

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        out = []
        for start in range(0, X.shape[0], 256):
            out.append(softmax(self.forward(X[start : start + 256])))
        return np.vstack(out) if out else np.zeros((0, self.n_classes))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.predict_proba(X).argmax(axis=1)

    # -- persistence --------------------------------------------------------

    def save(self, path: str) -> None:
        arrays: dict[str, Any] = {f"p{i}": p for i, p in enumerate(self._params())}
        np.savez_compressed(
            path,
            n_classes=self.n_classes,
            signal_len=self.signal_len,
            **arrays,
        )

    @classmethod
    def load(cls, path: str) -> "EspCNN":
        data = np.load(path)
        net = cls(int(data["n_classes"]), int(data["signal_len"]))
        target = net._params()
        for i, arr in enumerate(target):
            arr[...] = data[f"p{i}"]
        return net
