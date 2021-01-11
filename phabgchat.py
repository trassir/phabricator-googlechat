#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json as j
import os
import logging
from logging import getLogger

import tornado.web as tw
import tornado.ioloop

def parse_args():
    class EnvDefault(argparse.Action):
        def __init__(self, envvar, required=True, default=None, **kwargs):
            if envvar in os.environ:
                default = os.environ[envvar]
            if required and default:
                required = False
            super().__init__(default=default, required=required, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)


    p = argparse.ArgumentParser()
    p.add_argument('--phabricator', action=EnvDefault, envvar='PHABGCHAT_PHABRICATOR_URL')
    p.add_argument('--phabricator_hmac', action=EnvDefault, envvar='PHABGCHAT_PHABRICATOR_HMAC')
    p.add_argument('--gchat_webhook', action=EnvDefault, envvar='PHABGCHAT_GCHAT_WEBHOOK_URL')
    p.add_argument('--port', action=EnvDefault, envvar='PHABGCHAT_PORT', type=int)
    p.add_argument('--log-notime', action='store_true')
    return p.parse_args()


logger = getLogger(__name__)


class PhabReciever(tw.RequestHandler):
    def initialize(self, phabricator, gchat, hmac):
        self.phabricator = phabricator
        self.gchat = gchat
        self.hmac = hmac

    def post(self):
        try:
            logger.info(f'look, a POST!\nbody: {self.request.body}\nheaders: {self.request.headers}')

            if not self.request.headers.get('Content-Type') == 'application/json':
                m = 'not a json'
                logger.info(m)
                self.set_status(400, m)
                return self.finish()

            if self.hmac:
                signature_sent = self.request.headers.get('X-Phabricator-Webhook-Signature')
                if not signature_sent:
                    m = 'no phabricator signature'
                    logger.info(m)
                    self.set_status(401, m)
                    return self.finish()
                signature_calculated = hmac.new(
                    self.hmac.encode(),
                    msg=self.request.body,
                    digestmod=hashlib.sha256
                ).hexdigest()
                if signature_calculated != signature_sent:
                    m = f'phabricator signature mismatch; in header: {signature_sent}, calculated: {signature_calculated}'
                    logger.info(m)
                    self.set_status(401, m)
                    return self.finish()
            msg = j.loads(self.request.body)
            logger.info(f'POST data enqueued as {j.dumps(msg,indent=2)}')
        except Exception as e:
            logger.error(e)
            self.set_status(500)
            self.finish(j.dumps(dict(error=f'Some internal server error: {e}')))


class TornadoServer(tw.Application):
    def __init__(self, port: int, handlers):
        super().__init__([
            tw.url('/', tw.RequestHandler),
            *handlers
        ])
        self.port = port
        logger.info(f'Tornado app created @ port {self.port}')

    def run(self):
        self.listen(self.port)
        logger.info('Tornado serving forever')
        tornado.ioloop.IOLoop.instance().start()


def main():
    args = parse_args()

    fmt = '%(name)s - %(levelname)s - %(message)s'
    if not args.log_notime:
        fmt = '%(asctime)s - '+fmt
    logging.basicConfig(format=fmt, level=logging.INFO)

    ws = TornadoServer(int(args.port), [
        tw.url('/post', PhabReciever, dict(
            phabricator=args.phabricator,
            gchat=args.gchat_webhook,
            hmac=args.phabricator_hmac
        )),
    ])
    ws.run()


if __name__ == "__main__":
    main()
