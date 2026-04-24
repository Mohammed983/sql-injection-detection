"""SQL injection detection pipeline using TF-IDF and Linear SVM."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import ConfusionMatrixDisplay, accuracy_score, classification_report
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


RANDOM_STATE = 42
EXPECTED_COLUMNS = {"Query", "Label"}
DEFAULT_THRESHOLDS = [-0.6, -0.4, -0.2, 0.0, 0.2]
DEFAULT_CLASS_WEIGHT = {0: 1.0, 1: 2.0}
THRESHOLD = -0.4
MODEL_FILENAME = "sql_injection_svm_model.joblib"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Train and evaluate an SQL injection detector."
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("Modified_SQL_Dataset.csv"),
        help="Path to the input CSV file.",
    )
    parser.add_argument(
        "--figure",
        type=Path,
        default=Path("confusion_matrix_tuned.png"),
        help="Path to save the confusion matrix figure.",
    )
    parser.add_argument(
        "--thresholds",
        type=float,
        nargs="+",
        default=DEFAULT_THRESHOLDS,
        help="Decision thresholds to test for malicious classification.",
    )
    parser.add_argument(
        "--malicious-weight",
        type=float,
        default=DEFAULT_CLASS_WEIGHT[1],
        help="Class weight for malicious samples.",
    )
    parser.add_argument(
        "--normal-weight",
        type=float,
        default=DEFAULT_CLASS_WEIGHT[0],
        help="Class weight for normal samples.",
    )
    parser.add_argument(
        "--max-features",
        type=int,
        default=50000,
        help="Maximum number of TF-IDF features to keep.",
    )
    parser.add_argument(
        "--no-show",
        action="store_true",
        help="Disable displaying the confusion matrix window.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed evaluation output, including CV and threshold tables.",
    )
    return parser.parse_args()


def load_and_preprocess_data(csv_path: Path) -> tuple[pd.Series, pd.Series]:
    """Load the dataset and apply the required preprocessing steps."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)

    missing_columns = EXPECTED_COLUMNS.difference(df.columns)
    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}. "
            f"Expected columns: {sorted(EXPECTED_COLUMNS)}"
        )

    df = df[["Query", "Label"]].copy()
    df["Query"] = df["Query"].astype(str)
    df["Query"] = df["Query"].str.strip()
    df = df[df["Query"] != ""]
    df = df.drop_duplicates()

    df["Label"] = pd.to_numeric(df["Label"], errors="raise").astype(int)
    invalid_labels = sorted(set(df["Label"]) - {0, 1})
    if invalid_labels:
        raise ValueError(
            f"Unexpected label values found: {invalid_labels}. "
            "Labels must be 0 (normal) or 1 (malicious)."
        )

    if df["Label"].nunique() < 2:
        raise ValueError("The dataset must contain both normal and malicious samples.")

    return df["Query"], df["Label"]


def build_pipeline(max_features: int, class_weight: dict[int, float]) -> Pipeline:
    """Create the TF-IDF + Linear SVM pipeline."""
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 6),
                    lowercase=True,
                    max_features=max_features,
                    strip_accents="unicode",
                ),
            ),
            (
                "classifier",
                LinearSVC(
                    class_weight=class_weight,
                    max_iter=10000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


def run_cross_validation(
    model: Pipeline, features: pd.Series, labels: pd.Series, verbose: bool
) -> None:
    """Run 5-fold stratified cross-validation and optionally print details."""
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, features, labels, cv=cv, scoring="accuracy")

    if verbose:
        print("\nCross-validation results")
        for fold_index, score in enumerate(cv_scores, start=1):
            print(f"Fold {fold_index} accuracy: {score:.4f}")
        print(f"Mean accuracy: {cv_scores.mean():.4f}")
        print(f"Standard deviation: {cv_scores.std():.4f}")


def predict_with_threshold(scores, threshold: float):
    """Convert decision scores into class predictions using a custom threshold."""
    return (scores >= threshold).astype(int)


def summarize_threshold(y_true: pd.Series, y_pred, threshold: float) -> dict[str, float]:
    """Compute security-relevant metrics for one threshold."""
    _, fp, fn, _ = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=[1],
        average=None,
        zero_division=0,
    )

    return {
        "threshold": threshold,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_malicious": float(precision[0]),
        "recall_malicious": float(recall[0]),
        "f1_malicious": float(f1[0]),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    }


def evaluate_thresholds(y_true: pd.Series, scores, thresholds: list[float]) -> list[dict[str, float]]:
    """Evaluate a list of thresholds and return the metrics."""
    return [
        summarize_threshold(y_true, predict_with_threshold(scores, threshold), threshold)
        for threshold in thresholds
    ]


def select_operating_threshold(results: list[dict[str, float]]) -> dict[str, float]:
    """Use the fixed operating threshold for the final model."""
    if not results:
        raise ValueError("No threshold results were provided.")

    for metrics in results:
        if abs(metrics["threshold"] - THRESHOLD) < 1e-12:
            return metrics

    available_thresholds = ", ".join(f"{metrics['threshold']:.2f}" for metrics in results)
    raise ValueError(
        f"Selected threshold {THRESHOLD:.2f} was not evaluated. "
        f"Available thresholds: {available_thresholds}"
    )


def build_confusion_matrix_figure(
    y_true: pd.Series, y_pred
) -> tuple[plt.Figure, plt.Axes]:
    """Build a confusion matrix for the chosen threshold."""
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(
        y_true,
        y_pred,
        display_labels=["Normal", "Malicious"],
        cmap="Blues",
        colorbar=False,
        ax=ax,
    )
    ax.set_title("SQL Injection Detection Confusion Matrix - Tuned SVM")
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    fig.tight_layout()
    return fig, ax


def print_threshold_tuning_results(results: list[dict[str, float]]) -> None:
    """Print the full threshold tuning table."""
    print("\nThreshold tuning results")
    for metrics in results:
        print(
            f"Threshold {metrics['threshold']:>5.2f} | "
            f"accuracy={metrics['accuracy']:.4f} | "
            f"precision_malicious={metrics['precision_malicious']:.4f} | "
            f"recall_malicious={metrics['recall_malicious']:.4f} | "
            f"f1_malicious={metrics['f1_malicious']:.4f} | "
            f"false_positives={metrics['false_positives']} | "
            f"false_negatives={metrics['false_negatives']}"
        )


def print_final_summary(best_result: dict[str, float], figure_path: Path) -> None:
    """Print the concise final summary."""
    print("\nFinal evaluation")
    print(f"Selected threshold: {best_result['threshold']:.2f}")
    print(f"Final accuracy: {best_result['accuracy']:.4f}")
    print(f"Final malicious precision: {best_result['precision_malicious']:.4f}")
    print(f"Final malicious recall: {best_result['recall_malicious']:.4f}")
    print(f"Final malicious F1-score: {best_result['f1_malicious']:.4f}")
    print(f"False positives: {best_result['false_positives']}")
    print(f"False negatives: {best_result['false_negatives']}")
    print(f"Confusion matrix saved to: {figure_path.resolve()}")


def print_final_classification_report(y_true: pd.Series, y_pred) -> None:
    """Print the final classification report for the selected threshold."""
    print("\nFinal classification report")
    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["Normal", "Malicious"],
            digits=4,
            zero_division=0,
        )
    )


def evaluate_model(
    model: Pipeline,
    x_train: pd.Series,
    x_test: pd.Series,
    y_train: pd.Series,
    y_test: pd.Series,
    thresholds: list[float],
    verbose: bool,
) -> tuple[plt.Figure, dict[str, float], pd.Series, list[dict[str, float]]]:
    """Fit the model, tune the threshold, and build the final confusion matrix."""
    model.fit(x_train, y_train)
    scores = model.decision_function(x_test)

    threshold_results = evaluate_thresholds(y_test, scores, thresholds)
    if verbose:
        print_threshold_tuning_results(threshold_results)

    best_result = select_operating_threshold(threshold_results)
    final_predictions = pd.Series(
        predict_with_threshold(scores, best_result["threshold"]),
        index=y_test.index,
    )
    fig, _ = build_confusion_matrix_figure(y_test, final_predictions)
    return fig, best_result, final_predictions, threshold_results


def main() -> None:
    """Execute the end-to-end training and evaluation pipeline."""
    args = parse_args()
    class_weight = {0: args.normal_weight, 1: args.malicious_weight}

    queries, labels = load_and_preprocess_data(args.data)
    model = build_pipeline(args.max_features, class_weight)

    print("Dataset summary")
    print(f"Samples after preprocessing: {len(queries)}")
    print(f"Normal samples: {(labels == 0).sum()}")
    print(f"Malicious samples: {(labels == 1).sum()}")

    run_cross_validation(model, queries, labels, verbose=args.verbose)

    x_train, x_test, y_train, y_test = train_test_split(
        queries,
        labels,
        test_size=0.20,
        stratify=labels,
        random_state=RANDOM_STATE,
    )

    if args.verbose:
        print("\nTrain/test split")
        print(f"Training samples: {len(x_train)}")
        print(f"Test samples: {len(x_test)}")

    fig, best_result, final_predictions, _ = evaluate_model(
        model,
        x_train,
        x_test,
        y_train,
        y_test,
        thresholds=args.thresholds,
        verbose=args.verbose,
    )
    joblib.dump(model, MODEL_FILENAME)
    fig.savefig(args.figure, dpi=300, bbox_inches="tight")
    print_final_summary(best_result, args.figure)
    print(f"Model saved to {MODEL_FILENAME} with threshold = -0.40")

    if args.verbose:
        print_final_classification_report(y_test, final_predictions)

    if not args.no_show:
        plt.show()
    else:
        plt.close(fig)


if __name__ == "__main__":
    main()
