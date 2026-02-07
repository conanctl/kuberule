FROM docker.io/aquasec/trivy:latest

USER root

RUN apk add --no-cache curl bash jq

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

RUN curl -L -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/v4.44.3/yq_linux_amd64" && \
    chmod +x /usr/local/bin/yq

COPY run.sh /app/run.sh
COPY collectors.yaml /app/collectors.yaml
RUN chmod +x /app/run.sh

WORKDIR /app

ENTRYPOINT ["/app/run.sh"]
