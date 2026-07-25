"""SENTINEL dashboard package.

Module layout, in dependency order (each imports only from those above it, so
there are no import cycles):

    config       constants: paths, credentials, thresholds, correlation rules
    state        mutable shared state and the locks that guard it
    emailer      SMTP settings, sending, routing, digest batching
    correlation  cross-detector rule engine
    detectors    supervision of the five eBPF detector processes
    logtail      follows alerts.log; owns the email high-water mark
    web          Flask app, routes, JSON API

`Sentinel.py` at the project root is the entrypoint: it starts the background
threads and serves the app.
"""
