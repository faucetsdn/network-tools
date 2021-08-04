#!/usr/bin/env python3
import bjoern
import falcon
from falcon_cors import CORS

import routes

def make_api():
    cors = CORS(allow_all_origins=True)
    api = falcon.App(middleware=[cors.middleware])
    r = routes.routes()
    for route in r:
        api.add_route(route, r[route])
    return api


if __name__ == "__main__":
    bjoern.run(make_api(), "0.0.0.0", 8080)  # nosec
