FROM golang:latest

RUN git clone https://github.com/cbeuw/Cloak.git
WORKDIR Cloak
RUN make
