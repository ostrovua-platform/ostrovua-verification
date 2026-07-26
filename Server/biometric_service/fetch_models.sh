#!/bin/sh
set -eu

destination="${1:-/models}"
mkdir -p "$destination"

fetch() {
  url="$1"
  output="$2"
  expected="$3"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 --output "$output" "$url"
  actual=$(sha256sum "$output" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "model checksum mismatch: $output" >&2
    exit 1
  fi
}

opencv_commit="47534e27c9851bb1128ccc0102f1145e27f23f98"
fetch \
  "https://github.com/opencv/opencv_zoo/raw/${opencv_commit}/models/face_recognition_sface/face_recognition_sface_2021dec.onnx" \
  "$destination/sface.onnx" \
  "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79"
fetch \
  "https://github.com/opencv/opencv_zoo/raw/${opencv_commit}/models/face_detection_yunet/face_detection_yunet_2023mar.onnx" \
  "$destination/yunet.onnx" \
  "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"
fetch \
  "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task" \
  "$destination/face_landmarker.task" \
  "64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff"
