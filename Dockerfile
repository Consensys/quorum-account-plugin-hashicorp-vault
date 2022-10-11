FROM golang:1.18

RUN apt update && \
    apt install -y unzip zip

RUN mkdir -p /src

RUN wget https://releases.hashicorp.com/vault/1.11.4/vault_1.11.4_linux_amd64.zip -O /tmp/vault_1.11.4_linux_amd64.zip && \
      unzip /tmp/vault_1.11.4_linux_amd64.zip -d /usr/local/bin/

RUN git clone https://github.com/ConsenSys/quorum-signer-plugin-for-hashicorp-vault.git /src/quorum-signer-plugin-for-hashicorp-vault && \
    cd /src/quorum-signer-plugin-for-hashicorp-vault && \
    go mod tidy && \
    make

RUN git clone https://github.com/ConsenSys/quorum.git /src/quorum && \
    cd /src/quorum && \
    go mod tidy && \
    make all && \
    cp /src/quorum/build/bin/* /usr/local/bin/

COPY . /src/quorum-account-plugin-hashicorp-vault/

RUN cd /src/quorum-account-plugin-hashicorp-vault/ && \
    go mod tidy && \
    make

WORKDIR /src/quorum-account-plugin-hashicorp-vault/

ENV PLUGIN_DIST=/src/quorum-account-plugin-hashicorp-vault/build/dist
ENV PLUGIN_VERSION=0.2.0-SNAPSHOT
ENV VAULT_SIGNER_DIR=/src/quorum-signer-plugin-for-hashicorp-vault/build/dist
ENV VAULT_SIGNER_NAME=quorum-signer-0.2.2-SNAPSHOT-linux-amd64

CMD /bin/bash
