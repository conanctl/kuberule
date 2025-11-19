FROM aquasec/trivy:latest

USER root

RUN apk add --no-cache curl bash jq

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

WORKDIR /app

ENTRYPOINT ["/app/run.sh"]
