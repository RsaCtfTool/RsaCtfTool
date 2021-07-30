FROM alpine:3.13
RUN apk update && \
    apk add --no-cache \ 
    gmp-dev mpfr-dev mpc1-dev python3 python3-dev py3-pip gcc musl-dev openssl-dev libffi-dev py3-wheel git gcc g++ make cmake git
WORKDIR /opt
RUN git clone https://github.com/Ganapati/RsaCtfTool.git
WORKDIR /opt/RsaCtfTool
RUN pip install -r "requirements.txt"
WORKDIR /data
ENTRYPOINT ["/opt/RsaCtfTool/RsaCtfTool.py"]
