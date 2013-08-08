#!/usr/bin/env python
import BaseHTTPServer
import urlparse
import auth
import os
import simplejson as json

"""
  Usage example for the auth library (auth.py and associated auth.js; should be packaged with this).
  
  Created by Anthony Bau in 2013.

  This software is public domain.
"""

session_keys = {}
key_verifiers = {}

class AuthServer(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    conn = auth.initDB("test.db")
    parsed_url = urlparse.urlparse(self.path)
    path = parsed_url.path.split("/")
    qwargs = urlparse.parse_qs(parsed_url.query)
      
    #Enforce one value per query string arg
    for key in qwargs:
      qwargs[key] = qwargs[key][0]
    
    if (len(path) == 0 or path[1] == "index.html"):
      self.send_response(200)
      self.send_header("Content-Type", "text/html")
      self.end_headers()
      
      index_file = open("test.html", "r")
      self.wfile.write(index_file.read())
      index_file.close()
    elif (path[1] == "jslib"):
      self.send_response(200)
      self.send_header("Content-Type", "text/html")
      self.end_headers()
      
      js_file = open("/".join(path), "r")
      self.wfile.write(js_file.read())
      js_file.close()
    elif (path[1] == "register"):
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.end_headers()
      
      self.wfile.write(json.dumps({
        "success": auth.createUser(conn, qwargs["uname"], qwargs["verifier"], qwargs["salt"])
      }))
    elif (path[1] == "authenticate"):
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.end_headers()

      kdict = auth.generateKey(conn, qwargs["uname"], int(qwargs["A"], 16))
      session_keys[qwargs["uname"]] = kdict["K"]
      key_verifiers[qwargs["uname"]] = kdict["M"]

      print "Generated sesssion key %s." % auth.hexify(kdict["K"])

      self.wfile.write(json.dumps({
        "s": kdict["s"],
        "B": kdict["B"]
      }))
    elif (path[1] == "echo"):
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.end_headers()

      self.wfile.write(json.dumps({
        "cleartext":auth.decrypt(session_keys[qwargs["uname"]], qwargs["message"])
      }))
    else:
      self.send_response(404)
      self.send_header("Content-Type", "text/plain")
      self.end_headers()

      self.wfile.write("What are you talking about")

def run(server_class=BaseHTTPServer.HTTPServer, handler_class=AuthServer):
  server_address = ('', 8080)
  httpd = server_class(server_address, handler_class)
  httpd.serve_forever()

run()
