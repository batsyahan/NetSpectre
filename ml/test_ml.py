"""Unit tests for the ML service. Run from ml/:  python -m unittest -v test_ml"""
import re
import unittest
from pathlib import Path

import grpc
import numpy as np

import server
from explain import TEXT, explain

RUST = Path(__file__).resolve().parent.parent / "core" / "src" / "main.rs"


class FakeContext:
    def abort(self, code, msg):
        raise RuntimeError((code, msg))


def rust_feature_names():
    src = RUST.read_text()
    body = src.split("fn features(&self)", 1)[1].split("]\n    }", 1)[0]
    return re.findall(r'^\s*\("([^"]+)",', body, re.M)


class FeatureContract(unittest.TestCase):
    def test_35_features(self):
        self.assertEqual(server.n_feat, 35)
        self.assertEqual(len(server.FEATURES), 35)

    def test_every_feature_has_explanation_text(self):
        self.assertEqual({f.strip() for f in server.FEATURES}, {t.strip() for t in TEXT})

    def test_rust_extractor_matches_model_feature_order(self):
        rust = [n.strip() for n in rust_feature_names()]
        model = [n.strip() for n in server.FEATURES]
        self.assertEqual(rust, model, "Rust feature order must equal the model's training order")


class Classify(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(0)
        self.x = rng.uniform(0, 5000, server.n_feat).astype(np.float32).tolist()

    def test_wrong_length_is_rejected(self):
        with self.assertRaises(ValueError):
            server.classify([0.0] * (server.n_feat - 1))
        with self.assertRaises(ValueError):
            server.classify([0.0] * (server.n_feat + 1))

    def test_output_is_well_formed(self):
        out = server.classify(self.x)
        self.assertIn(out.label, server.classes)
        self.assertGreater(out.confidence, 0.0)
        self.assertLessEqual(out.confidence, 1.0 + 1e-6)
        self.assertGreaterEqual(out.anomaly_score, 0.0)
        self.assertLessEqual(len(out.reasons), 3)
        if out.label == "BENIGN":
            self.assertEqual(len(out.reasons), 0)

    def test_deterministic(self):
        a, b = server.classify(self.x), server.classify(self.x)
        self.assertEqual((a.label, a.confidence, a.anomaly_score), (b.label, b.confidence, b.anomaly_score))

    def test_servicer_aborts_with_invalid_argument(self):
        req = server.pb.FlowFeatures(features=[1.0, 2.0])
        with self.assertRaises(RuntimeError) as cm:
            server.Inference().Classify(req, FakeContext())
        self.assertEqual(cm.exception.args[0][0], grpc.StatusCode.INVALID_ARGUMENT)


class Explanations(unittest.TestCase):
    def test_top3_sorted_and_shares_sum_to_100(self):
        rng = np.random.default_rng(1)
        checked = 0
        for _ in range(20):
            x = rng.uniform(0, 5000, (1, server.n_feat)).astype(np.float32)
            k = int(np.argmax(server.probs(server.sess_x, x)))
            out = explain(server.booster, x, k, server.FEATURES)
            self.assertLessEqual(len(out), 3)
            if out:
                shares = [w for _, _, w in out]
                self.assertAlmostEqual(sum(shares), 100.0, places=4)
                self.assertEqual(shares, sorted(shares, reverse=True))
                for name, text, _ in out:
                    self.assertIn(name, server.FEATURES)
                    self.assertTrue(text)
                checked += 1
        self.assertGreater(checked, 0, "no random flow produced any explanation")


class AnomalyScore(unittest.TestCase):
    def test_extreme_outlier_scores_higher_than_typical_flow(self):
        typical = np.expm1(server._mu)[None, :].astype(np.float32)           # z = 0 (the training mean)
        outlier = np.expm1(server._mu + 10 * server._sd)[None, :].astype(np.float32)  # +10 sd on every feature
        self.assertGreater(server.anomaly(outlier), server.anomaly(typical))

    def test_scores_are_finite_and_non_negative(self):
        for x in (np.zeros((1, server.n_feat)), np.full((1, server.n_feat), 1e9)):
            s = server.anomaly(x.astype(np.float32))
            self.assertTrue(np.isfinite(s))
            self.assertGreaterEqual(s, 0.0)


if __name__ == "__main__":
    unittest.main()
