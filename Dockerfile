FROM python:3.10

ENV PROTOC_VERSION 24.4

ARG TARGETARCH

RUN if [ "$TARGETARCH" = "amd64" ]; then \
        arch="x86_64"; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        arch="aarch_64"; \
    else \
        exit 1; \
    fi \
    && curl -o /tmp/protoc.zip -L \
        https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${arch}.zip \
    && unzip /tmp/protoc.zip -d /usr -x readme.txt \
    && rm /tmp/protoc.zip

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
