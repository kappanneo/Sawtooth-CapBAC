import datetime
import logging
import time
import json

import asyncio

import aiocoap.resource as resource
import aiocoap

from colorlog import ColoredFormatter # version 2.6

from subprocess import check_output

def print(string:str): # true printf() debugging
    logging.getLogger(__name__).debug(msg=string)

class SimpleResource(resource.Resource):
    """Example resource which supports the GET and PUT methods."""

    def __init__(self):
        super().__init__()
        self.content= b"this is an important string\n"

    async def render_get(self, request):
        print('Raw payload: %s' % request.payload)
        split_payload = request.payload.split("#",1)
        error = call(['capbac','validate',split_payload[0]])
        if (error):
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)
        else: 
            return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        print('Payload: %s' % request.payload)
        self.content= request.payload + b"\n"
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)

class TimeResource(resource.ObservableResource):
    """Example resource that can be observed. The `notify` method keeps
    scheduling itself, and calles `update_state` to trigger sending
    notifications."""

    def __init__(self):
        super().__init__()

        self.handle = None

    def notify(self):
        self.updated_state()
        self.reschedule()

    def reschedule(self):
        self.handle = asyncio.get_event_loop().call_later(5, self.notify)

    def update_observation_count(self, count):
        if count and self.handle is None:
            print("Starting the clock")
            self.reschedule()
        if count == 0 and self.handle:
            print("Stopping the clock")
            self.handle.cancel()
            self.handle = None

    async def render_get(self, request):
        payload = datetime.datetime.now().\
                strftime("%Y-%m-%d %H:%M\n").encode('ascii')
        return aiocoap.Message(payload=payload)

# logging setup

    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s.%(msecs)03d %(levelname)-8s %(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(clog)

def main():

    logging.getLogger(__name__).info(msg="Running server...")

    # Root token issuing
    capability_token = {
        "ID":"0000000000000000",
        "DE": "coap://device",    
        "AR": [{
            "AC": "GET",
            "RE": "time",
            "DD": 100
        }, {
            "AC": "GET",
            "RE": "resource",
            "DD": 100
        }, {
            "AC": "PUT",
            "RE": "resource",
            "DD": 100
        }],
        "NB": str(int(time.time())),
        "NA": "2000000000"
    }

    try:
        logging.getLogger(__name__).info("Issuing root token...")
        response = check_output(["capbac","issue","--root",json.dumps(capability_token)]).decode("utf-8") 
        link = json.loads(response)["link"]

        logging.getLogger(__name__).info('Checking result...')
        for i in range(5):
            time.sleep(5)
            response = check_output(["curl","--silent",link]).decode("utf-8")
            status = json.loads(response)["data"][0]["status"]
            print(status)
            if(status == "INVALID"):
                raise Exception("Token not committed.")
            elif(status == "COMMITTED"):
                logging.getLogger(__name__).info("Token committed.")
                break

    except Exception as e:
        print(e)
        logging.getLogger(__name__).error(msg="Cannot issue root token, aborting...")
        return 1

    # Resource tree creation
    root = resource.Site()

    root.add_resource(('.well-known', 'core'),
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(('time',), TimeResource())
    root.add_resource(('resource',), SimpleResource())
    
    asyncio.Task(aiocoap.Context.create_server_context(root))

    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()