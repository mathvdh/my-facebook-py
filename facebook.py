#!/usr/bin/env python
#
# My facebook.py
# Author : Mathieu Van der Haegen <mathvdh@gmail.com>
#
# This work is based on facebook.py as can be found at https://github.com/facebook/python-sdk/
# It is also based on other code found here and there but I don't know exactly where
# So if you find some of your code here, let me know I can add a reference to you.
#
#

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Python client library for the Facebook Platform.

This client library is designed to support the Graph API and the official
Facebook JavaScript SDK, which is the canonical way to implement
Facebook authentication. Read more about the Graph API at
http://developers.facebook.com/docs/api. You can download the Facebook
JavaScript SDK at http://github.com/facebook/connect-js/.

If your application is using Google AppEngine's webapp framework, your
usage of this module might look like this:

   user = facebook.get_user_from_cookie(self.request.cookies, key, secret)
   if user:
       graph = facebook.GraphAPI(user["access_token"])
       profile = graph.get_object("me")
       friends = graph.get_connections("me", "friends")

"""


import cgi
import hashlib
import time
import urllib
import base64
import datetime
import hmac

from django.conf import settings
from django.http import HttpResponseRedirect,HttpResponse,HttpResponseNotFound
from base.models import *

# Find a JSON parser
try:
	import json
	_parse_json = lambda s: json.loads(s)
except ImportError:
	try:
		import simplejson
		_parse_json = lambda s: simplejson.loads(s)
	except ImportError:
		# For Google AppEngine
		from django.utils import simplejson
		_parse_json = lambda s: simplejson.loads(s)


class fbsig_redirect(object):
    def __init__(self, orig_func):
        self.orig_func = orig_func

    def __call__(self, request, *args, **kwargs):
        sigreq =request.POST.get('signed_request', None)
        fb = Facebook()

        if sigreq != None:
            fb.load_signed_request(sigreq)

            if fb.user_id and fb.access_token:
                    request.fbObject = fb
                    return self.orig_func(request, *args, **kwargs)

            else:
                return fb.build_authentication_redirect()

        else:
            return fb.build_authentication_redirect()


class fbsig_required(object):
    def __init__(self, orig_func):
        self.orig_func = orig_func

    def __call__(self, request, *args, **kwargs):
        sigreq =request.POST.get('signed_request', None)
        fb = Facebook()

        if sigreq != None:
            fb.load_signed_request(sigreq)

            if fb.user_id and fb.access_token:
                request.fbObject = fb
                return self.orig_func(request, *args, **kwargs)


            else:
                return HttpResponseNotFound('<h1>You need to be authentified!</h1>')
        else:
            return HttpResponseNotFound('<h1>You need to be authentified!</h1>')


class GraphAPIError(Exception):
	def __init__(self, type, message):
		Exception.__init__(self, message)
		self.type = type


class Facebook(object):
	"""Wraps the Facebook specific logic"""
	def __init__(self, app_id=settings.FACEBOOK_APP_ID,
		app_secret=settings.FACEBOOK_APP_SECRET,
		req_perms=settings.FACEBOOK_REQ_PERMS,
		redirect_uri=settings.CANVAS_URI):
		self.app_id = app_id
		self.app_secret = app_secret
		self.req_perms = req_perms
		self.redirect_uri = redirect_uri
		self.user_id = None
		self.access_token = None
		self.signed_request = {}
		self.coded_signed_request = None

	def get_object(self, id, **args):
		"""Fetchs the given object from the graph."""
		return self.request(id, args)

	def get_objects(self, ids, **args):
		"""Fetchs all of the given object from the graph.

		We return a map from ID to object. If any of the IDs are invalid,
		we raise an exception.
		"""
		args["ids"] = ",".join(ids)
		return self.request("", args)

	def get_connections(self, id, connection_name, **args):
		"""Fetchs the connections for given object."""
		return self.request(id + "/" + connection_name, args)

	def put_object(self, parent_object, connection_name, **data):
		"""Writes the given object to the graph, connected to the given parent.

		For example,

		    graph.put_object("me", "feed", message="Hello, world")

		writes "Hello, world" to the active user's wall. Likewise, this
		will comment on a the first post of the active user's feed:

		    feed = graph.get_connections("me", "feed")
		    post = feed["data"][0]
		    graph.put_object(post["id"], "comments", message="First!")

		See http://developers.facebook.com/docs/api#publishing for all of
		the supported writeable objects.

		Most write operations require extended permissions. For example,
		publishing wall posts requires the "publish_stream" permission. See
		http://developers.facebook.com/docs/authentication/ for details about
		extended permissions.
		"""
		assert self.access_token, "Write operations require an access token"
		return self.request(parent_object + "/" + connection_name, post_args=data)

	def put_wall_post(self, message, attachment={}, profile_id="me"):
		"""Writes a wall post to the given profile's wall.

		We default to writing to the authenticated user's wall if no
		profile_id is specified.

		attachment adds a structured attachment to the status message being
		posted to the Wall. It should be a dictionary of the form:

		{"name": "Link name"
		"link": "http://www.example.com/",
		"caption": "{*actor*} posted a new review",
		"description": "This is a longer description of the attachment",
		"picture": "http://www.example.com/thumbnail.jpg"}

		"""
		return self.put_object(profile_id, "feed", message=message, **attachment)

	def put_comment(self, object_id, message):
		"""Writes the given comment on the given post."""
		return self.put_object(object_id, "comments", message=message)

	def put_like(self, object_id):
		"""Likes the given post."""
		return self.put_object(object_id, "likes")

	def delete_object(self, id):
		"""Deletes the object with the given ID from the graph."""
		self.request(id, post_args={"method": "delete"})

	def request(self, path, args=None, post_args=None):
		"""Fetches the given path in the Graph API.

		We translate args to a valid query string. If post_args is given,
		we send a POST request to the given path with the given arguments.
		"""
		if not args: args = {}
		if self.access_token:
			if post_args is not None:
				post_args["access_token"] = self.access_token
			else:
				args["access_token"] = self.access_token

			post_data = None if post_args is None else urllib.urlencode(post_args)
			file = urllib.urlopen("https://graph.facebook.com/" + path + "?" + urllib.urlencode(args), post_data)
			try:
				response = _parse_json(file.read())
			finally:
				file.close()

			if response.get("error"):
				raise GraphAPIError(response["error"]["type"],response["error"]["message"])

			return response

	def load_signed_request(self, signed_request):
		"""Load the user state from a signed_request value"""
		self.coded_signed_request = signed_request
		sig, payload = signed_request.split(u'.', 1)
		sig = self.base64_url_decode(sig)
		data = json.loads(self.base64_url_decode(payload))

		expected_sig = hmac.new(self.app_secret, msg=payload, digestmod=hashlib.sha256).digest()

		# allow the signed_request to function for upto 1 day
		if sig == expected_sig and data[u'issued_at'] > (time.time() - 86400):
			self.signed_request = data
			self.user_id = data.get(u'user_id')
			self.access_token = data.get(u'oauth_token')

	def build_authentication_redirect(self):
		args = {}
		args["client_id"]=self.app_id
		args["redirect_uri"]=self.redirect_uri
		args["scope"]=",".join(self.req_perms)
		redirect_url = "https://www.facebook.com/dialog/oauth?"+urllib.urlencode(args)
		redirect_code = """
			<script type="text/javascript">
			top.location.href='%s';
			</script>
		""" % redirect_url;
		return HttpResponse(redirect_code,mimetype="text/html")

	def get_user_from_cookie(cookies, app_id, app_secret):
		"""Parses the cookie set by the official Facebook JavaScript SDK.

		cookies should be a dictionary-like object mapping cookie names to
		cookie values.

		If the user is logged in via Facebook, we return a dictionary with the
		keys "uid" and "access_token". The former is the user's Facebook ID,
		and the latter can be used to make authenticated requests to the Graph API.
		If the user is not logged in, we return None.

		Download the official Facebook JavaScript SDK at
		http://github.com/facebook/connect-js/. Read more about Facebook
		authentication at http://developers.facebook.com/docs/authentication/.
		"""
		cookie = cookies.get("fbs_" + app_id, "")
		if not cookie: return None
		args = dict((k, v[-1]) for k, v in cgi.parse_qs(cookie.strip('"')).items())
		payload = "".join(k + "=" + args[k] for k in sorted(args.keys())
		                  if k != "sig")
		sig = hashlib.md5(payload + app_secret).hexdigest()
		expires = int(args["expires"])
		if sig == args.get("sig") and (expires == 0 or time.time() < expires):
			return args
		else:
			return None



	@property
	def user_cookie(self):
		"""Generate a signed_request value based on current state"""
		if not self.user_id:
			return
		payload = self.base64_url_encode(json.dumps({
			u'user_id': self.user_id,
			u'issued_at': str(int(time.time())),
		}))

		sig = self.base64_url_encode(hmac.new(self.app_secret, msg=payload, digestmod=hashlib.sha256).digest())
		return sig + '.' + payload

	@staticmethod
	def base64_url_decode(data):
		data = data.encode(u'ascii')
		data += '=' * (4 - (len(data) % 4))
		return base64.urlsafe_b64decode(data)

	@staticmethod
	def base64_url_encode(data):
		return base64.urlsafe_b64encode(data).rstrip('=')

