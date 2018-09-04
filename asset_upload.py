import requests
import json
import sys
import os
import re


class SecurityCenter():
    
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
            headers['X-SecurityCenter'] = str(self._token)
        if self._cookie != '':
            headers['Cookie'] = self._cookie

        # Only convert the data to JSON if there is data.
        if data is not None:
            data = json.dumps(data)

        url = "https://{0}/rest/{1}".format(self._server, resource)

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
        except requests.ConnectionError as e:
            print(str(e))
            return None

        #Uncomment for Debugging or to redirect to a log file

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
        except(ValueError , e):
            print (e)
            print("no JSON")
            return None

        # If the response status is not 200 OK, there is an error.
        if contents['error_code'] != 0:
            print(contents['error_msg'])
            return None

        # Return the contents of the response field from the SecurityCenter
        # response.
        return contents['response']


    def analysis(self, query, limit=100):
        """
        Queries the SC server for a list of vulnerabilities or events that
        match the given parameters. The SC server is queried for results in
        groups of 1000. Yields results that match the parameters or None if
        there is an error. Returns no more than limit results.
        """

        received = 0
        step = 1000
        query['startOffset'] = 0
        query['endOffset'] = 0
        total = limit

        if query.get('id') is not None:
            input = {'type': 'vuln',
                     'sourceType': 'cumulative',
                     'query': query}
        else:
            input = {'type': query['type'],
                     'sourceType': query['subtype'],
                     'query': query}

        while (received < limit) and (received < total):

            # If my endOffset is larger than max, set it to max.
            if received + step > limit:
                query['endOffset'] = limit
            else:
                query['endOffset'] += step

            """
            For additional troubleshooting, you can uncomment the following two lines of code.
            Uncommenting them will display the QUERY and INPUT strings in the output
            """
            #print 'QUERY:\n{0}\n'.format(query)
            #print 'INPUT:\n{0}\n'.format(input)

            response = self.connect('POST', 'analysis', input)

            # There is an error
            if response is None:
                received = limit + 1
                continue

            # process the returned records
            received += response['returnedRecords']
            total = int(response['totalRecords'])
            print('Received {0} of {1} records.'.format(received,total))

            for v in response['results']:
                yield v

            query['startOffset'] = query['endOffset']

if __name__ == '__main__':

    requests.packages.urllib3.disable_warnings()
    if (len(sys.argv) != 2):
        print ("\n[!] Takes one argument")
        print ("\n[*] Usage: python asset_upload.py <Asset-Name>\n")
        sys.exit(0)

    #grabs creds from a file

    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(dir_path + '/creds', 'r')

    uname = f.readline().strip()
    password = f.readline().strip()
    IP = f.readline().strip()

    sc = SecurityCenter(IP)
    sc.login(uname, password)

    if sc.authenticated():

        try:
            resp = sc.connect('GET', 'asset')
        except:
            e = sys.exc_info()[0]
            #print (e)
            print ("Couldn't get assets")
            sys.exit(0)

        #Finds ID from for the asset name in args, then uploads IPs to that asset from a txt file of the same name

        asset = sys.argv[1]
        for v in resp['usable']:
            if v['name'] == asset:
                try:
                    f = open(asset +'.txt', 'r')
                    list=""
                    for ip in f:
                        list= list + str(ip)

                    input={'definedIPs' : list}
                    resp = sc.connect('PATCH', 'asset/'+ v['id'], input)
                    print("[*] " + asset + " updated")
                except:
                    e = sys.exc_info()[0]
                    #print (e)
                    print("Something is wrong with you file or asset could not be updated")
                    sys.exit(0)
        sc.logout()
