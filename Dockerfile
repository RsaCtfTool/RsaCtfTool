FROM python:3-alpine
RUN apk update && \
    apk add --no-cache \
    gmp-dev mpfr-dev mpc1-dev gcc musl-dev openssl-dev libffi-dev git gcc g++ make cmake git
WORKDIR /app
COPY . .
RUN pip install -r "requirements.txt"
WORKDIR /data
ENTRYPOINT ["/app/RsaCtfTool.py"]
