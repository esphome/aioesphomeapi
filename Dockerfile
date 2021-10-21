FROM python:3.10

RUN \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler=3.12.4-1 \
        libprotobuf-dev=3.12.4-1 \
    && rm -rf \
        /tmp/* \
        /var/{cache,log}/* \
        /var/lib/apt/lists/*

WORKDIR /aioesphomeapi

COPY requirements_test.txt ./

RUN pip3 install -r requirements_test.txt

CMD ["script/gen-protoc"]

LABEL \
    org.opencontainers.image.title="aioesphomeapi protobuf generator" \
    org.opencontainers.image.description="An image to help with ESPHomes aioesphomeapi protobuf generation" \
    org.opencontainers.image.vendor="ESPHome" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.url="https://esphome.io" \
    org.opencontainers.image.source="https://github.com/esphome/aioesphomeapi" \
    org.opencontainers.image.documentation="https://github.com/esphome/aioesphomeapi/blob/main/README.md"
