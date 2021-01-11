#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import logging
from logging import getLogger

from phabricator import Phabricator
import requests
import tornado.ioloop
import tornado.web as tw

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
    p.add_argument('--phabricator', action=EnvDefault, envvar='PHABGCHAT_PHABRICATOR_URL', required=False)
    p.add_argument('--phabricator_token', action=EnvDefault, envvar='PHABGCHAT_PHABRICATOR_TOKEN', required=False)
    p.add_argument('--phabricator_hmac', action=EnvDefault, envvar='PHABGCHAT_PHABRICATOR_HMAC')
    p.add_argument('--gchat_webhook', action=EnvDefault, envvar='PHABGCHAT_GCHAT_WEBHOOK_URL')
    p.add_argument('--port', action=EnvDefault, envvar='PHABGCHAT_PORT', type=int)
    p.add_argument('--log-notime', action='store_true')
    return p.parse_args()


logger = getLogger(__name__)


class PhabGchat:
    def __init__(self, phab: Phabricator, hmac: str, gchat: str):
        self.gchat = gchat
        self.hmac = hmac
        self.phab = phab
        h = phab.host.rstrip('/')
        if h.endswith('/api'):
            h = h[:-len('/api')]
        self.phab_host = h


    def validate_request(self, body, headers):
        if not headers.get('Content-Type') == 'application/json':
            m = 'not a json'
            logger.info(m)
            return m

        if not self.hmac:
            return None

        signature_sent = headers.get('X-Phabricator-Webhook-Signature')
        if not signature_sent:
            m = 'no phabricator signature header'
            logger.info(m)
            return m

        signature_calculated = hmac.new(
            self.hmac.encode(),
            msg=body,
            digestmod=hashlib.sha256
        ).hexdigest()

        if signature_calculated != signature_sent:
            m = f'phabricator signature mismatch; in header: {signature_sent}, calculated: {signature_calculated}'
            logger.info(m)
            return m

        return None


    def process(self, j):
        o = j.get('object')
        if not o:
            logger.error('no "object" key in json')
            return
        t = o.get('type')
        if t != 'TASK':
            logger.warning(f'can work only with object type TASK, got {t} instead')
            return
        p = o.get('phid')
        logger.info(f'querying phabricator for task {p}')
        query = self.phab.maniphest.search(constraints=dict(phids=[p])).data
        if not query:
            logger.error('no task found')
            return
        task = query[0]

        task_id = task['id']
        f = task['fields']
        task_name = f['name']

        a = f['authorPHID']
        logger.info(f'querying phabricator for user {a}')
        u = self.phab.user.search(constraints=dict(phids=[a])).data[0]
        username = u['fields']['realName']

        msg = f'Ticket <{self.phab_host}/T{task_id}|T{task_id}> reported by {username}: ```{task_name}```'
        logger.info(f'{msg}\nSending to google chat...')

        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        requests.post(self.gchat, headers=headers, json=dict(text=msg))
        logger.info('DONE.')


class PhabReciever(tw.RequestHandler):
    def initialize(self, pg: PhabGchat):
        self.interactor = pg

    def post(self):
        try:
            logger.debug('POST!\nbody: %s\nheaders: %s', self.request.body, self.request.headers)
            vmsg = self.interactor.validate_request(self.request.body, self.request.headers)
            if vmsg:
                self.set_status(400, vmsg)
                return self.finish()

            msg = json.loads(self.request.body)
            self.interactor.process(msg)

        except Exception as e:
            logger.error(e)
            self.set_status(500, f'Some internal server error: {e}')
            self.finish()


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


    phab = Phabricator(host=args.phabricator, token=args.phabricator_token)
    logger.info('updating phabricator interfaces...')
    phab.update_interfaces()
    logger.info(f'working with {phab.host}')

    interactor = PhabGchat(phab, args.phabricator_hmac, args.gchat_webhook)

    ws = TornadoServer(int(args.port), [
        tw.url('/post', PhabReciever, dict(
            pg=interactor,
        )),
    ])
    ws.run()


if __name__ == "__main__":
    main()
