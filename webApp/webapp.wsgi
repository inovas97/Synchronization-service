#!/usr/bin/python3
import sys
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/webApp/")
from webApp.app import app as application
application.secret_key = "8f5fbf876bd5fdf345e4c01413c29b8d"
