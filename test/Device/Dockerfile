FROM python:stretch

RUN pip install aiocoap

COPY . .

EXPOSE 5683 

CMD ["python3","server.py"]
