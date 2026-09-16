FROM python:3.13-slim-trixie AS builder

RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes \
        gcc libc6-dev libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/local/bin/python3.13 /usr/bin/python3.13

RUN python3 -m venv --copies /venv
RUN /venv/bin/pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" wheel

COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --no-cache-dir -r /requirements.txt

RUN mkdir -p /app/data && chown 65532:65532 /app/data

FROM gcr.io/distroless/python3-debian13:nonroot

COPY --from=builder /venv /venv
COPY --from=builder /usr/local/lib/libpython3.13.so.1.0 /venv/lib/libpython3.13.so.1.0
COPY --from=builder /usr/local/lib/libpython3.13.so /venv/lib/libpython3.13.so

WORKDIR /app
COPY --chown=nonroot:nonroot app.py /app/app.py
COPY --chown=65532:65532 --from=builder /app/data /app/data

ENV PYTHONPATH="/venv/lib/python3.13/site-packages"

EXPOSE 5000

ENTRYPOINT ["/usr/bin/python3.13"]
CMD ["app.py"]
