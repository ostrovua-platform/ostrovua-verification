#!/usr/bin/env python3
"""Export the two pinned MiniFASNet checkpoints to deterministic ONNX files."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import torch


EXPECTED_INPUTS = {
    "2.7_80x80_MiniFASNetV2.pth":
        "a5eb02e1843f19b5386b953cc4c9f011c3f985d0ee2bb9819eea9a142099bec0",
    "4_0_0_80x80_MiniFASNetV1SE.pth":
        "84ee1d37d96894d5e82de5a57df044ef80a58be2b218b5ed7cdfd875ec2f5990",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()
    expected = EXPECTED_INPUTS.get(source.name)
    if expected is None or sha256(source) != expected:
        raise SystemExit(f"refusing unpinned checkpoint: {source}")

    upstream = source.parents[2]
    sys.path.insert(0, str(upstream))
    from src.anti_spoof_predict import MODEL_MAPPING  # pylint: disable=import-outside-toplevel
    from src.utility import get_kernel, parse_model_name  # pylint: disable=import-outside-toplevel

    height, width, model_type, _scale = parse_model_name(source.name)
    model = MODEL_MAPPING[model_type](conv6_kernel=get_kernel(height, width))
    state = torch.load(source, map_location="cpu", weights_only=True)
    if next(iter(state)).startswith("module."):
        state = {key.removeprefix("module."): value for key, value in state.items()}
    model.load_state_dict(state)
    model.eval()

    output.parent.mkdir(parents=True, exist_ok=True)
    sample = torch.zeros((1, 3, height, width), dtype=torch.float32)
    torch.onnx.export(
        model,
        sample,
        output,
        input_names=["input"],
        output_names=["logits"],
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )
    print(f"{output.name} {sha256(output)}")


if __name__ == "__main__":
    main()
