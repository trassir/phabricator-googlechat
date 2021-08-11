#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import logging
from logging import getLogger
from typing import Any, Optional

from phabricator import Phabricator
import requests
from tornado.httputil import HTTPHeaders
import tornado.ioloop
import tornado.web as tw

def parse_args() -> argparse.Namespace:
    class EnvDefault(argparse.Action):
        def __init__(self, envvar: str, required: bool=True, default: Any=None, **kwargs: Any):
            if envvar in os.environ:
                default = os.environ[envvar]
            if required and default:
                required = False
            super().__init__(default=default, required=required, **kwargs)

        def __call__(self, parser: Any, namespace: Any, values: Any, option_string: Any=None) -> None:
            setattr(namespace, self.dest, values)


    p = argparse.ArgumentParser()
    p.add_argument('--phabricator', action=EnvDefault, envvar='PHABCHAT_PHABRICATOR_URL', required=False)
    p.add_argument('--phabricator_token', action=EnvDefault, envvar='PHABCHAT_PHABRICATOR_TOKEN', required=False)
    p.add_argument('--phabricator_hmac', action=EnvDefault, envvar='PHABCHAT_PHABRICATOR_HMAC')
    p.add_argument('--teams_webhook', action=EnvDefault, envvar='PHABCHAT_TEAMS_WEBHOOK_URL')
    p.add_argument('--port', action=EnvDefault, envvar='PHABCHAT_PORT', type=int)
    p.add_argument('--log-notime', action='store_true')
    return p.parse_args()


logger = getLogger(__name__)


class PhabChat:
    def __init__(self, phab: Phabricator, hmac: str, teams_url: str):
        self.teams_url = teams_url
        self.hmac = hmac
        self.phab = phab
        h = phab.host.rstrip('/')
        if h.endswith('/api'):
            h = h[:-len('/api')]
        self.phab_host = h


    def validate_request(self, body: bytes, headers: HTTPHeaders) -> Optional[str]:
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


    def process(self, j: dict[str, Any]) -> None:
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

        self.send(task_name, task_id, username)


    def send(self, task_name: str, task_id: int, username: str) -> None:
        T = f'T{task_id}'
        url = f'{self.phab_host}/{T}'
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "4a5f88",
            "summary": "n/a",
            "sections": [{
                "activityTitle": f"{T}: {task_name}",
                "facts": [
                    {
                        "name": "Reported by:",
                        "value": username
                    },
                    {
                        "name": "URL:",
                        "value": url
                    }
                ],
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "Open",
                "targets": [{
                    "os": "default",
                    "uri": url
                }]
            }]
        }
        logger.info(f'Sending to microsoft teams:\n{payload}')
        requests.post(self.teams_url, json=payload)
        logger.info('DONE.')


class PhabReciever(tw.RequestHandler):
    def initialize(self, pg: PhabChat) -> None:
        self.interactor = pg

    def post(self) -> None:
        try:
            logger.debug('POST!\nbody: %s\nheaders: %s', self.request.body, self.request.headers)
            vmsg = self.interactor.validate_request(self.request.body, self.request.headers)
            if vmsg:
                self.set_status(400, vmsg)
                self.finish()
                return

            msg = json.loads(self.request.body)
            self.interactor.process(msg)

        except Exception as e:
            logger.error(e)
            self.set_status(500, f'Some internal server error: {e}')
            self.finish()


class TornadoServer(tw.Application):
    def __init__(self, port: int, handlers: Any):
        super().__init__([
            tw.url('/', tw.RequestHandler),
            *handlers
        ])
        self.port = port
        logger.info(f'Tornado app created @ port {self.port}')

    def run(self) -> None:
        self.listen(self.port)
        logger.info('Tornado serving forever')
        tornado.ioloop.IOLoop.instance().start()


def main() -> None:
    args = parse_args()

    fmt = '%(name)s - %(levelname)s - %(message)s'
    if not args.log_notime:
        fmt = '%(asctime)s - '+fmt
    logging.basicConfig(format=fmt, level=logging.INFO)


    phab = Phabricator(host=args.phabricator, token=args.phabricator_token)
    logger.info('updating phabricator interfaces...')
    phab.update_interfaces()
    logger.info(f'working with {phab.host}')

    interactor = PhabChat(phab, args.phabricator_hmac, args.teams_webhook)

    ws = TornadoServer(int(args.port), [
        tw.url('/post', PhabReciever, dict(
            pg=interactor,
        )),
    ])
    ws.run()


if __name__ == "__main__":
    main()
