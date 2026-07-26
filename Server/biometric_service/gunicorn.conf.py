bind = "0.0.0.0:8080"
workers = 1
threads = 1
worker_class = "sync"
# Do not initialize native CV runtimes in the long-lived master. Each worker
# loads models, serves exactly one request, and then the OS destroys the whole
# address space. This also avoids unsafe fork-after-MediaPipe initialization.
preload_app = False
max_requests = 1
max_requests_jitter = 0
timeout = 45
graceful_timeout = 5
keepalive = 0
accesslog = None
errorlog = "-"
loglevel = "warning"
capture_output = False
worker_tmp_dir = "/dev/shm"
