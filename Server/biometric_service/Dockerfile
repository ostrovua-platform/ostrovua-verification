FROM alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS models
RUN apk add --no-cache ca-certificates curl
WORKDIR /build
COPY fetch_models.sh /build/fetch_models.sh
RUN sh /build/fetch_models.sh /models

FROM python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    BIOMETRIC_MODEL_DIR=/app/models \
    BIOMETRIC_MODEL_MANIFEST=/app/model_manifest.json
RUN apt-get update && apt-get install --yes --no-install-recommends libgl1 libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 12001 biometric && \
    useradd --system --uid 12001 --gid biometric --home-dir /nonexistent --shell /usr/sbin/nologin biometric
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY --from=models /models /app/models
COPY models/*.onnx /app/models/
COPY model_manifest.json policy.py calibration.py document_auth.py replay_cache.py \
     envelope.py engine.py evaluate.py app.py gunicorn.conf.py /app/
COPY tools/generate_runtime_secrets.py /app/tools/generate_runtime_secrets.py
RUN python -c "from engine import BiometricEngine; BiometricEngine.from_environment(); print('model integrity OK')" && \
    chown -R root:root /app && chmod -R a+rX,go-w /app
USER 12001:12001
EXPOSE 8080
CMD ["gunicorn", "--config", "/app/gunicorn.conf.py", "app:app"]
