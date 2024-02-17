FROM ubuntu:24.04

RUN apt update && apt install -y socat

RUN groupadd --gid 1001 pwn

RUN useradd --uid 1001 --gid 1001 --home-dir /home/pwn --create-home --shell /sbin/nologin pwn

WORKDIR /home/pwn

COPY task .

COPY flag.txt .

RUN chmod +x ./task

EXPOSE 9001

USER pwn

CMD ["socat", "tcp-listen:9001,fork,reuseaddr", "exec:./task"]
