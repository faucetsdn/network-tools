#!/usr/bin/env python3
import bjoern
import falcon
from falcon_cors import CORS

import routes


cors = CORS(allow_all_origins=True)
api = application = falcon.App(middleware=[cors.middleware])

r = routes.routes()
for route in r:
    api.add_route(route, r[route])


if __name__ == "__main__":
    bjoern.run(api, "0.0.0.0", 8080)
