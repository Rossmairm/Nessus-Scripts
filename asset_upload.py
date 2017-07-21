import requests
import json
import sys
import os
import re


class SecurityCenter:

    def __init__(self, server, verify_ssl=False):
        self._server = server
        self._verify = verify_ssl
        self._token = ''
        self._cookie = ''

    def authenticated(self):
        """
        Determine whether we are authenticated to the server.

        If the self._token is not empty then we are authenticated otherwise we
        are not.
        """
        if self._token == '':
            return False
        else:
            return True

    def login(self, username, password):
        """
        Login to the SecurityCenter server and set the token.

        Send a POST request to the token endpoint with the username and
        password. If the authentication request was successful, the server
        will return a token that must be sent in the Authentication header of
        all subsequent requests.
        """
        input = {'username': username, 'password': password}
        resp = self.connect('POST', 'token', input)
        if resp is not None:
            self._token = resp['token']
            #print self._token

    def logout(self):
        """
        Logout of the SecurityCenter server.

        Send a DELETE request to the token endpoint and delete the stored
        token and cookie.
        """
        self.connect('DELETE', 'token')
        self._token = ''
        self._cookie = ''

    def connect(self, method, resource, data=None):
        """
        Send a request to SecurityCenter server.

        Use the method, resource and data to build a request to send to the
        SecurityCenter server. If the session token and cookie are available,
        add them to the request headers. Also specify the content-type as JSON
        and check for any errors in the response. """
        headers = {
            'Content-Type': 'application/json',
        }

        if self._token != '':
            headers['X-SecurityCenter'] = self._token
        if self._cookie != '':
            headers['Cookie'] = self._cookie

        # Only convert the data to JSON if there is data.
        if data is not None:
            data = json.dumps(data)

        url = "https://{0}/rest/{1}".format(self._server, resource)
        #print('Making {0} request to {1}'.format(method, resource))
        try:
            if method == 'POST':
                r = requests.post(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PUT':
                r = requests.put(url, data=data, headers=headers, verify=self._verify)
            elif method == 'DELETE':
                r = requests.delete(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PATCH':
                r = requests.patch(url, data=data, headers=headers, verify=self._verify)
            else:
                r = requests.get(url, params=data, headers=headers, verify=self._verify)
        except requests.ConnectionError, e:
            print str(e)
            print "we got here"
            return None

        #print('Request Headers: {0}'.format(r.request.headers))
        #print('Request Data: {0}'.format(r.request.body))
        #print('Response Headers: {0}'.format(r.headers))
        #print('Response Data: {0}'.format(r.content))

        if r.headers.get('set-cookie') is not None:
            match = re.findall("TNS_SESSIONID=[^,]*", r.headers.get('set-cookie'))
            self._cookie = match[1]

        # Make sure we have a JSON response. If not then return None.
        try:
            contents = r.json()
        except ValueError as e:
           # print (e)
            print "no JSON"
            return None

        # If the response status is not 200 OK, there is an error.
        if contents['error_code'] != 0:
            #print(contents['error_msg'])
            return None

        # Return the contents of the response field from the SecurityCenter
        # response.
        return contents['response']



if __name__ == '__main__':

    requests.packages.urllib3.disable_warnings()

   #grabs creds from a file

    f = open('creds', 'r')
    uname= f.readline().strip()
    password=f.readline().strip()

    sc = SecurityCenter('54.236.31.85')
    sc.login(uname, password)

    if sc.authenticated():

        resp = sc.connect('GET', 'asset')

        #Grabs IP from a file and uploads them to SC based on input

        asset = sys.argv[1]
        for v in resp['usable']:
            if v['name'] == asset:
                f = open(asset +'.txt', 'r')
                list=""
                for ip in f:
                    list= list + str(ip)

                    print list
                    input={'definedIPs' : list}
                resp = sc.connect('PATCH', 'asset/'+ v['id'], input)
        """
        Call to logout
        """


        sc.logout()



