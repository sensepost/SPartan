#!/bin/python
# -*- coding: utf-8 -*-
"""
SPartan is a Frontpage and Sharepoint eviscerator, great for mutilating Sharepoint sites.
Features:
- Sharepoint and Frontpage fingerprinting
- Manages Friendly 404s
- Default Sharepoint and Frontpage file and folder enumeration
- Identify PUTable directories
- Download identified files, including detection of uninterpreted ASP and ASPX
- Search for keywords in identified pages
- Saves state from previous scans
- Site crawling
- Accepts NTLM creds for authenticated scans


Prerequisite# are:
+ requests_ntlm
+ beautifulsoup4

Author: Special K
Version: 1.0 (20-11-2014)

"""
import argparse,requests,sys,os,threading,bs4,warnings,random
from threading import Lock
from requests_ntlm import HttpNtlmAuth


warnings.filterwarnings("ignore")

#TODO
#Frontpage RPCs
#Intelligent versioning for RPCs based on FPVersion
#----------------------------------------------------------------------------------------------------------------------------------------------

foundURLs = []
# threadCount = 10
counter = 0
dirs = []
filename = ''
# downloadFiles = False
RED = "\033[00;31m{0}\033[00m"
GREEN = "\033[00;32m{0}\033[00m"
BLUE = "\033[00;34m{0}\033[00m"
CYAN = "\033[00;36m{0}\033[00m"
YELLOW = "\033[00;33m{0}\033[00m"
PURPLE = "\033[00;35m{0}\033[00m"

agents = ['Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3'
'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) ChroMe/4.0.219.6 Safari/532.1',
'Mozilla/4.0 (coMpatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
'Mozilla/4.0 (coMpatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
'Mozilla/4.0 (coMpatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
'Mozilla/4.0 (coMpatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)', 
'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
'Mozilla/4.0 (coMpatible; MSIE 6.1; Windows XP)']
#----------------------------------------------------------------------------------------------------------------------------------------------


def getUsers(url):
    path = '_layouts/people.aspx?MembershipGroupId=0'
    userList = []

    thread = URLThread(url + '/' + stringCleaner(path))
    thread.start()
    thread.join()

    response = thread.resp
    if response is not None:
        soup = bs4.BeautifulSoup(response.text)
        for inputTag in soup.find_all('input'):
            accountElement = inputTag.get('account')
            if accountElement is not None:
                if 'i:0#.f|' in accountElement or 'i:0#.w|' in accountElement:
                    print accountElement.rsplit('|', 1)[1]
                else:
                    print accountElement

def writeUserToFile(accName):
    fname = fileNamer(url)
    if checkDirExists(fname):
        f = open(fname + '/users.txt', 'a')
        f.write(accName + '\n')
        f.close()

def xmlSOAPUserParse(xmlString):
    #Parse soap xml for people.asmx
    soap = bs4.BeautifulSoup(xmlString)
    users = []
    for principal in soap.find_all('principalinfo'):
        user = []
        for tag in principal:
            user.append('%s:%s' % (tag.name, tag.string))
        users.append(user)
    return users

def signal_handler(signal, frame):
    sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

#Frontpage guts
def frontpage_fingerprint(url):
    linux_paths = ['_vti_bin/_vti_aut/author.exe', '_vti_bin/_vti_adm/admin.exe', '_vti_bin/shtml.exe']
    win_paths = ['_vti_bin/_vti_aut/author.dll', '_vti_bin/_vti_aut/dvwssr.dll', '_vti_bin/_vti_adm/admin.dll',
                 '_vti_bin/shtml.dll']

    #Check Linux
    for path in linux_paths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        thread.join()
        resp = thread.resp
        if resp is not None and len(resp.text) > 0:
            print "\n[+] Frontpage for Linux found"
            break

    #Check Windows
    for path in win_paths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        thread.join()
        resp = thread.resp
        if resp is not None and len(resp.text) > 0:
            print "\n[+] Frontpage for Windows found"
            break

    thread = URLThread(url + '/_vti_inf.html')
    thread.start()
    thread.join()
    resp = thread.resp
    if resp is not None and len(resp.text) > 0:
        print"[+] Frontpage config: " + resp.text


def frontpage_bin(url):
    with open("front_bin.txt") as f:
        layoutPaths = f.readlines()
    for path in layoutPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        thread.join()


def frontpage_pvt(url):
    with open("front_pvt.txt") as f:
        layoutPaths = f.readlines()
    for path in layoutPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        thread.join()


def frontpage_services(url):
    with open("front_serv.txt") as f:
        layoutPaths = f.readlines()
    for path in layoutPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        thread.join()


def frontpage_rpc(url):
    paths = ['_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/shtml.dll/_vti_rpc']
    dataList = ['method=list+services:3.0.2.1076&service_name=', 'method=list+services:4.0.2.471&service_name=',
                'method=list+services:4.0.2.0000&service_name=', 'method=list+services:5.0.2.4803&service_name=',
                'method=list+services:5.0.2.2623&service_name=', 'method=list+services:6.0.2.5420&service_name=']

    for path in paths:
        for data in dataList:
            thread = URLThread(None)
            thread.start()
            thread.join()
            thread.sendData(url + '/' + path, data)
            resp = thread.resp
            if resp is not None and resp.status_code == 200:
                print resp.text


def query_rpc(url, query):
    paths = ['_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/shtml.dll/_vti_rpc']
    data = "method=" + query
    path = ''
    for path in paths:
        try:
            resp = URLThread(url + '/' + path.strip("/"))
            if resp.status_code == 200:
                break
        except Exception:
            pass
    try:
        resp = URLThread(url + '/' + path.strip("/"))
        if resp.status_code == 200:
            print resp.text
    except requests.HTTPError, e:
        print e


def frontpage_fileup(url):
    return


def frontpage_folder_del(url):
    return


def frontpage_serv_enum(url):
    return


def frontpage_config_enum(url):
    return


#Sharepoint innards
def sharepoint_fingerprint(url):
    try:
        thread = URLThread(url)
        thread.start()
        thread.join()
        resp = thread.resp
        if 'microsoftsharepointteamservices' in resp.headers:
            print "[+] Sharepoint version: " + resp.headers['microsoftsharepointteamservices']
        if 'x-aspnet-version' in resp.headers:
            print "[+] X-Aspnet version: " + resp.headers['x-aspnet-version']
        if 'x-sharepointhealthscore' in resp.headers:
            print "[+] Sharepoint health score: " + resp.headers['x-sharepointhealthscore']
    except requests.HTTPError, e:
        print e


def sharepoint_layouts(url):
    with open("sp_layouts.txt") as f:
        layoutPaths = f.readlines()
    threads = []
    for path in layoutPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()


def sharepoint_forms(url):
    with open("sp_forms.txt") as f:
        formPaths = f.readlines()
    threads = []
    for path in formPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()


def sharepoint_catalogs(url):
    with open("sp_catalogs.txt") as f:
        catPaths = f.readlines()
    threads = []
    for path in catPaths:
        thread = URLThread(url + '/' + stringCleaner(path))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

def soap_services(url):
    #Test for exposed SOAP services (look for docRef in spsdisco)
    thread = URLThread(url + '/' + stringCleaner('_vti_bin/spsdisco.aspx'))
    thread.start()
    thread.join()
    resp = thread.resp
    threads = []

    soup = bs4.BeautifulSoup(resp.text)
    for disc in soup.find_all('discovery'):
        for contract in disc.find_all('contractref'):
            docref = contract.get('docref')
            thread = URLThread(stringCleaner(docref))
            thread.start()
            threads.append(thread)

    for t in threads:
        t.join()

def getVerbs(u):
    url = u.strip()
    headers = {'user-agent': random.choice(agents).strip(),}
    try:
        verbs = []
        if requests.get(url,headers=headers).status_code == 200:
            verbs.append('GET')
        if requests.post(url, 'test',headers=headers).status_code == 200:
            verbs.append('POST')
        if requests.head(url,headers=headers).status_code == 200:
            verbs.append('HEAD')
        if requests.delete(url,headers=headers).status_code == 200:
            verbs.append('DELETE')
        if requests.put(url, 'test',headers=headers).status_code == 200:
            verbs.append('PUT')
        if requests.options(url,headers=headers).status_code == 200:
            verbs.append('OPTIONS')

        return verbs

    except requests.HTTPError, e:
        print e


def findPuttable():
    #Find directories which are puttable
    headers = {'user-agent': random.choice(agents).strip(),}
    paths = []
    try:
        for url in foundURLs:
                urlPath = url.split('/')
                if len(urlPath) > 3:
                    urlPath.pop()
                newURL = '/'.join(urlPath)
                if newURL not in paths:
                    paths.append(newURL)
        for path in paths:
            resp = None
            if authed:
                resp = requests.options(path, auth=HttpNtlmAuth(username, password),headers=headers)
            else:
                resp = requests.options(path,headers=headers)

            if resp is not None and resp.status_code == 200:
                if 'allow' in resp.headers:
                    printer('[+] PUT - %s' % (path), GREEN)

    except Exception, e:
        print e


def authenticate(url, userpass, cString):
    headers = {'user-agent': random.choice(agents).strip(),}
    try:
        global username
        global password
        global authed
        global cookie

        if userpass is not None:
            #use credentials
            username = userpass.split(':')[0]
            password = userpass.split(':')[1]
            print '[+] Authenticating: %s %s' % (url, username)
            response = requests.get(url, auth=HttpNtlmAuth(username, password), verify=ignore_ssl,headers=headers)
            if response.status_code == 200:
                print '[+] Authenticated...Have fun!: %s' % (response.status_code)
                authed = True
            else:
                print '[-] Failed! Have the gods no mercy?: %s' % (response.status_code)
                sys.exit(0)

        if cString is not None:
            #use a cookie
            cookie = {}
            cookieList = cString.strip(';').split(' ')
            for c in cookieList:
                params = c.partition('=')
                cookie.update({params[0]:params[2]})
            print '[+] Authenticating: %s' % (url)
            response = requests.get(url, cookies=cookie, verify=ignore_ssl,headers=headers)
            if response.status_code == 200:
                print '[+] Authenticated...Have fun!: %s' % (response.status_code)
                authed = True
            else:
                print '[-] Failed! Have the gods no mercy?: %s' % (response.status_code)
                sys.exit(0)

    except Exception, e:
        print e


#Entrail Crawler
def crawler(url):
    queue = foundURLs[:] #clone foundURLs. queue used for processing URLs and foundURLs used to prevent rescans
    urlList = url.split('/')
    baseURL = '/'.join(urlList[:3])
    headers = {'user-agent': random.choice(agents).strip(),}
    try:
        while len(queue) > 0:
            qURL = queue.pop(0)

            if authed:
                if cookie is not None:
                    response = requests.get(qURL, cookies=cookie, verify=ignore_ssl,headers=headers)
                else:
                    response = requests.get(qURL, auth=HttpNtlmAuth(username, password), verify=ignore_ssl,headers=headers)
            else:
                response = requests.get(qURL, verify=ignore_ssl,headers=headers)
            soup = bs4.BeautifulSoup(response.text)
            for link in soup.find_all('a'):
                hLink = link.get('href')
                if hLink is not None:
                    if '/' in hLink:
                        if 'http' in hLink:
                            if qURL in hLink and qURL not in foundURLs and '..' not in hLink:
                                #It's in scope
                                thread = URLThread(hLink)
                                thread.start()
                                thread.join()
                                if thread.resp.status_code == 200:
                                    queue.append(hLink)
                        else:
                            if (baseURL + '/' + hLink.strip('/')) not in foundURLs and '..' not in hLink:
                                thread = URLThread(baseURL + '/' + hLink.strip('/'))
                                thread.start()
                                thread.join()
                                if thread.resp.status_code == 200:
                                    queue.append(baseURL + '/' + hLink.strip('/'))
    except KeyboardInterrupt, e:
        return
    except Exception, e:
        print e

#Keyword scanner
def keywordScanner(keyword):
    headers = {'user-agent': random.choice(agents).strip(),}
    try:
        for url in foundURLs:
                resp = requests.get(url, verify=ignore_ssl,headers=headers)
                if keyword in resp.text or keyword in url:
                    printer('[+] Found keyword %s in %s' % (keyword, url), GREEN)
    except Exception, e:
        print e

def fileNamer(url):
    fileName = url.strip('https://').strip('http://').strip('/')
    fileName = fileName.replace(":","")
    if '/' in fileName:
        return fileName.split('/')[0]
    return fileName

def checkDirExists(fileName):
    if os.path.exists(fileName):
        return True
    return False

def checkFileExists(fileName):
    if os.path.isfile(fileName + '/' + fileName):
        return True
    return False


def restoreState(fileName):
    with open(fileName + '/' + fileName) as f:
        urls = f.readlines()
    for url in urls:
        foundURLs.append(stringCleaner(url))
    f.close()
    print '[+] %s URLs restored for this session' % (len(foundURLs))

    for url in foundURLs:
        printer('[+] ' + url, GREEN)

def saveState(fileName):
    with open(fileName + '/' + fileName, 'w') as f:
        f.writelines(("%s\n" % l.strip() for l in foundURLs))
    f.close()


def stringCleaner(text):
    return u''.join(text.split()).strip('/')

def printer(text, colour):
    sys.stdout.write(colour.format(text) + '\n')
    sys.stdout.flush()

#=======================================================================================================================
# threadLimiter = threading.BoundedSemaphore(threadCount)

class URLThread(threading.Thread):
    #Responsible for processing all URLs

    def __init__(self, urlName):
        threading.Thread.__init__(self)
        self.url = urlName
        self.resp = ''
        self.lock = Lock()

    def run(self):
        threadLimiter.acquire()
        try:
            #Only call this is no data was supplied
            if self.url is not None:
                self.urlProcessor(self.url)
        finally:
            threadLimiter.release()

    def urlProcessor(self, url):
        global foundURLs
        global counter
        ERROR1 = 'An error occurred'
        ERROR2 = 'Correlation ID'
        headers = {'user-agent': random.choice(agents).strip(),}
        try:
            #resp = None
            #Do a request with a bullshit url
            urlList = url.split('/')
            if len(urlList) > 3:
                urlList.pop()
            fakeUrl = '/'.join(urlList).strip('\n') + '/baaaaaaaa_said_the_sheepman.dll'
            fakeResp = None

            try:
                #Manage Friendly 404s
                #Checks whether dummy URL and actual URL produce same size response
                #Also uses a size error bound used in determining distance between dummy URL and actual URL and error message recognition
                errorBound = 50
                fakeRespSize = 0
                respSize = 0

                if authed:
                    if cookie is not None:
                        fakeResp = requests.get(fakeUrl, cookies=cookie, verify=ignore_ssl,headers=headers)
                    else:
                        fakeResp = requests.get(fakeUrl, auth=HttpNtlmAuth(username, password), verify=ignore_ssl,headers=headers)
                else:
                    fakeResp = requests.get(fakeUrl, verify=ignore_ssl,headers=headers)

                fakeRespSize = len(fakeResp.text)

            except requests.HTTPError, e:
                #If it's catching these then Friendly 404s are not being used and it's just fucking out
                pass

            #Do request with legit url
            if authed:
                if cookie is not None:
                    self.resp = requests.get(url, cookies=cookie, verify=ignore_ssl,headers=headers)
                else:
                    self.resp = requests.get(url, auth=HttpNtlmAuth(username, password), verify=ignore_ssl,headers=headers)
            else:
                self.resp = requests.get(url, verify=ignore_ssl,headers=headers)

            respSize = len(self.resp.text)

            #Determine response type and check whether it's a Friendly 404
            if (verbose == True) and (self.resp.status_code == 200) and (fakeResp is not None) and (fakeRespSize == respSize or (abs(respSize - fakeRespSize) < errorBound) or ERROR1 in self.resp.text or ERROR2 in self.resp.text):
                #This is a Friendly 404s
                out = "[-] [%s][%s][%sb] - %s" % (counter, 'Friendly 404', respSize, url.strip())
                self.printer(out, RED)
                counter = counter + 1
            else:
                #These are URLs that are found
                if self.resp.status_code == 200:
                    out = "[+] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, GREEN)
                    foundURLs.append(url)
                    if downloadFiles:
                        self.fileDownloader(url)
                if verbose == True:
                    if self.resp.status_code == 400:
                        out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                        self.printer(out, RED)
                    if self.resp.status_code == 404:
                        out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                        self.printer(out, RED)
                    if self.resp.status_code == 401 or self.resp.status_code == 403:
                        out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                        self.printer(out, BLUE)
                    if self.resp.status_code == 302:
                        out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                        self.printer(out, YELLOW)
                    if self.resp.status_code == 500:
                        out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                        self.printer(out, PURPLE)
                counter = counter + 1


        except requests.HTTPError, e:
            print e

    def sendData(self, url, data, headers):
        global counter
        try:
            if authed:
                if cookie is not None:
                    self.resp = requests.post(url, cookies=cookie, data=data, headers=headers, verify=ignore_ssl)
                else:
                    self.resp = requests.post(url, auth=HttpNtlmAuth(username, password), data=data, headers=headers, verify=ignore_ssl)
            else:
                self.resp = requests.post(url, data=data, headers=headers, verify=ignore_ssl)
            respSize = len(self.resp.text)

            if self.resp is not None:
                #if self.resp.status_code == 200:
                 #   out = "[+] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                  #  self.printer(out, GREEN)
                   # foundURLs.append(url)
                if self.resp.status_code == 400:
                    out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, RED)
                if self.resp.status_code == 404:
                    out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, RED)
                if self.resp.status_code == 401 or self.resp.status_code == 403:
                    out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, BLUE)
                if self.resp.status_code == 302:
                    out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, YELLOW)
                if self.resp.status_code == 500:
                    out = "[-] [%s][%s][%sb] - %s" % (counter, self.resp.status_code, respSize, url.strip())
                    self.printer(out, PURPLE)
                counter = counter + 1

        except Exception, e:
            print e

    def fileDownloader(self, url):
        #Download files to folder

        extList = url.split('.')
        extension = extList.pop()
        fileList = url.split('/')
        fName = fileList.pop()
        headers = {'user-agent': random.choice(agents).strip(),}
        if 'txt' in extension or 'stp' in extension or 'xlsx' in extension or 'xls' in extension or 'doc' in extension or 'docx' in extension or 'pdf' in extension or 'xml' in extension or 'config' in extension or 'conf' in extension or 'aspx' in extension or 'asp' in extension or 'webpart' in extension or 'csv' in extension:

            if authed:
                if cookie is not None:
                    self.resp = requests.get(url, cookies=cookie, stream=True, verify=ignore_ssl,headers=headers)
                else:
                    self.resp = requests.get(url, auth=HttpNtlmAuth(username, password), stream=True, verify=ignore_ssl,headers=headers)
            else:
                self.resp = requests.get(url, stream=True,headers=headers)

            if 'asp' in extension or 'aspx' in extension:
                if '<%' not in self.resp.text and '%>' not in self.resp.text:
                    #Interpreted asp and aspx must be ignored
                    out = "[+] Downloading: %s" % (fName)
                    self.printer(out, GREEN)

                    with open(fileName + '/' + fName, 'wb') as f:
                        for chunk in self.resp.iter_content(chunk_size=1024):
                            if chunk: # filter out keep-alive new chunks
                                f.write(chunk)
                                f.flush()

            out = "[+] Downloading: %s" % (fName)
            self.printer(out, GREEN)
            with open(fileName + '/' + fName, 'wb') as f:
                for chunk in self.resp.iter_content(chunk_size=1024):
                    if chunk: # filter out keep-alive new chunks
                        f.write(chunk)
                        f.flush()
            f.close()
    def printer(self, text, colour):
        with self.lock:
            sys.stdout.write(colour.format(text) + '\n')
            sys.stdout.flush()
#=======================================================================================================================


def banner():
    red = "\033[00;31m{0}\033[00m"
    banner = """
   ██████ ██▓███  ▄▄▄      ██▀███ ▄▄▄█████▓▄▄▄      ███▄    █
 ▒██    ▒▓██░  ██▒████▄   ▓██ ▒ ██▓  ██▒ ▓▒████▄    ██ ▀█   █
 ░ ▓██▄  ▓██░ ██▓▒██  ▀█▄ ▓██ ░▄█ ▒ ▓██░ ▒▒██  ▀█▄ ▓██  ▀█ ██▒
   ▒   ██▒██▄█▓▒ ░██▄▄▄▄██▒██▀▀█▄ ░ ▓██▓ ░░██▄▄▄▄██▓██▒  ▐▌██▒
 ▒██████▒▒██▒ ░  ░▓█   ▓██░██▓ ▒██▒ ▒██▒ ░ ▓█   ▓██▒██░   ▓██░
 ▒ ▒▓▒ ▒ ▒▓▒░ ░  ░▒▒   ▓▒█░ ▒▓ ░▒▓░ ▒ ░░   ▒▒   ▓▒█░ ▒░   ▒ ▒
 ░ ░▒  ░ ░▒ ░      ▒   ▒▒ ░ ░▒ ░ ▒░   ░     ▒   ▒▒ ░ ░░   ░ ▒░
 ░  ░  ░ ░░        ░   ▒    ░░   ░  ░       ░   ▒     ░   ░ ░
       ░               ░  ░  ░                  ░  ░        ░
               Sharepoint & Frontpage Scanner
"""
    print red.format(banner)


if __name__ == "__main__":

    banner()

    parser = argparse.ArgumentParser(prog='SPartan')
    parser.add_argument('-u', dest='url', action='store', help="host URL to scan including HTTP/HTTPS")
    parser.add_argument('-c', dest='crawl', action='store_true', help="crawl the site for links (CTRL-C to stop crawling)")
    parser.add_argument('-f', dest='frontpage', action='store_true', help="perform frontpage scans")
    parser.add_argument('-k', dest='keyword', action='store', help="scrape identified pages for keywords (works well with crawl)")
    parser.add_argument('-s', dest='sharepoint', action='store_true', help="perform sharepoint scans")
    parser.add_argument('--sps', dest='sps', action='store_true', help="discover sharepoint SOAP services")
    parser.add_argument('--users', dest='users', action='store_true', help="List users using Search Principals")
    parser.add_argument('-r', dest='rpc', action='store', help="(COMING SOON)execute a specified Frontpage RPC query")
    parser.add_argument('-t', dest='thread', action='store', help="set maximum amount of threads (10 default)")
    parser.add_argument('-p', dest='putable', action='store_true', help="(COMING SOON)find putable directories")
    parser.add_argument('--cookie', dest='cookie', action='store', help="use a cookie for authenticated scans")
    parser.add_argument('-d', dest='download', action='store_true', help="download pdf, doc, docx, txt, config, xml, xls, xlsx, webpart, config, conf, stp, csv and asp/aspx(uninterpreted)")
    parser.add_argument('-l', dest='login', action='store', help="provide credentials for authentication to Sharepoint",
                        metavar=('domain\user:password'))
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help="Render verbose output. By default SPartan will only render found resources.")
    parser.add_argument('-i', '--ignore-ssl-verification', dest='ignore_ssl', action='store_false', help="Don't attempt to verify SSL certificates as valid before making a request. This is defaulted to false.")
    args = parser.parse_args()

    try:
        if args.url:
            choice = 'n'

            global threadCount
            if args.thread:
                threadCount = args.thread
            else:
                threadCount = 10

            global threadLimiter
            threadLimiter = threading.BoundedSemaphore(threadCount)

            global downloadFiles
            if args.download:
                downloadFiles = True
            else:
                downloadFiles = False

            global cookie
            if args.cookie:
                cString = args.cookie
                authenticate(args.url, None, cString)
            else:
                cookie = None

            global authed
            if args.login:
                authenticate(args.url, args.login, None)
            else:
                authed = False

            global verbose
            verbose = False
            if args.verbose:
                verbose = True
                print 'Verbosity is set to HIGH. Spartan will print all resources found.'
            else:
                print 'Verbosity is set to LOW. SPartan will only print available resources. Use the -v flag to print all other resources found.'

            global ignore_ssl
            ignore_ssl = False
            if args.ignore_ssl:
                ignore_ssl = True

            url = args.url.strip('/')
            fileName = fileNamer(url)

            if not checkDirExists(fileName):
                os.makedirs(fileName)

            if checkFileExists(fileName):
                print "A file named %s already exists. Do you want to restore this session? [y/n]" % fileName
                choice = raw_input().lower()
                if choice != 'y' and choice != 'n':
                    printer('Bad choice!', RED)
                    sys.exit(0)
                if choice == 'y':
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Loading..."
                    restoreState(fileName)
            if choice == 'n' or not checkFileExists(fileName):
                #Inject the base URL
                thread = URLThread(url)
                thread.start()
                thread.join()

                if args.frontpage:
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Frontpage fingerprinting..."
                    frontpage_fingerprint(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Frontpage pvt scan..."
                    frontpage_pvt(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Frontpage bin scan..."
                    frontpage_bin(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Frontpage service scan..."
                    frontpage_services(url)
                    print "\n-----------------------------------------------------------------------------"
                    # print "[+] Initiating Frontpage RPC scan..."
                if args.sharepoint:
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Sharepoint fingerprinting..."
                    sharepoint_fingerprint(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Sharepoint layouts scan..."
                    sharepoint_layouts(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Sharepoint forms scan..."
                    sharepoint_forms(url)
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Initiating Sharepoint catalogs scan..."
                    sharepoint_catalogs(url)
                if args.sps:
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Searching for SOAP services..."
                    soap_services(url)
                if args.users:
                    print "\n-----------------------------------------------------------------------------"
                    print "[+] Listing user information..."
                    getUsers(url)
            if args.crawl:
                crawler(url)
            if args.keyword:
                print "\n-----------------------------------------------------------------------------"
                print "[+] Initiating keyword scan..."
                keywordScanner(stringCleaner(args.keyword))
            # if args.rpc:
            #     print "\n-----------------------------------------------------------------------------"
            #     print "[+] Executing Frontpage RPC query..."
            #     query_rpc(url, args.rpc)
            if args.putable:
                print "\n-----------------------------------------------------------------------------"
                print "[+] Searching for PUTable directories..."
                findPuttable()
            print "\n-----------------------------------------------------------------------------"
            print "[+] Saving state: " + fileName
            saveState(fileName)
    except Exception, e:
        print e
