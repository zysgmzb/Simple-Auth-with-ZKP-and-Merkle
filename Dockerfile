FROM --platform=linux/amd64 ubuntu:22.04

WORKDIR /app

COPY . /app

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt-get update -y && apt-get install -y curl git wget python3-pip
RUN wget https://github.com/ethereum/solidity/releases/download/v0.8.30/solc-static-linux -O /usr/local/bin/solc && chmod +x /usr/local/bin/solc
RUN python3 -m pip install -i https://mirror.nju.edu.cn/pypi/web/simple/ -r requirements.txt

RUN solc-select install 0.8.28 && solc-select use 0.8.28
 
ENV PATH="$PATH:/root/.foundry/bin"
ENV ANVIL_IP_ADDR=0.0.0.0
RUN curl -L https://foundry.paradigm.xyz | bash

RUN foundryup

RUN curl -LSfs get.zokrat.es | sh

ENV PATH="$PATH:/root/.zokrates/bin"

EXPOSE 5000

CMD flask run -h 0.0.0.0