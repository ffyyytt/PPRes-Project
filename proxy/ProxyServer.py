import os
import re
import ast
import sys
import signal
import socket
import threading

from urllib.parse import unquote

class ProxyServer:
    def __init__(self, port, headerRulesFile, inReplaceRulesFile, outReplaceRulesFile, blockRulesFile, rulesHTML, notFoundHTML, webSource, configServer, configPort):
        signal.signal(signal.SIGINT, self.close)
        self._port = port
        self._headerRulesFile = headerRulesFile # File save header rules
        self._headerRules = self.loadListRules(self._headerRulesFile) # Header rule (list), replace string startswith
        self._inReplaceRulesFile = inReplaceRulesFile # File save input rules
        self._inReplaceRules = self.loadReplaceRules(self._inReplaceRulesFile) # input rules (dictionary)
        self._outReplaceRulesFile = outReplaceRulesFile # file save output rules
        self._outReplaceRules = self.loadReplaceRules(self._outReplaceRulesFile) # output rules (dictionary)
        self._blockRulesFile = blockRulesFile # file save block rules
        self._blockRules = self.loadListRules(self._blockRulesFile) # block rules (list)
        self._rulesHTML = rulesHTML # file html default to visualise rule
        self._notFoundHTML = notFoundHTML # 404 html
        self._webSource = webSource # source of proxy config webset
        self._configServer = configServer # config URL
        self._configPort = configPort # port to config

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # re use address
        self._socket.bind(('', self._port)) # bind
        self._socket.listen(socket.SOMAXCONN) # set max connect

    def loadListRules(self, file):
        # To load a list rules (header, block)
        with open(file, "rb") as f:
            return list(map(lambda x:x.lower(), f.read().strip().splitlines()))

    def loadReplaceRules(self, file):
        # To load a dictionary rules (replace)
        with open(file, "r") as f:
            return ast.literal_eval("{" + f.read().strip() + "}")

    def close(self, signal, frame):
        #close socket
        self._socket.close()
        sys.exit(0)

    def start(self):
        # start proxy server
        while True:
            (clientSocket, clientAddress) = self._socket.accept() # accept connect
            t = threading.Thread(target = self.connect, args=(clientSocket, clientAddress))
            t.setDaemon(True) # low priority
            t.start()

    def parseURL(self, request):
        # get URL from request
        return request.split()[1]

    def parseHost(self, request):
        # get host and port from rquest
        if (b"Host" in request): # case HTTP/1.1
            hostFull = request[request.find(b"Host")+6:request.find(b"\r\n", request.find(b"Host"))].decode() # parse full host:port
        else:  # case HTTP/1.0
            hostFull = self.parseURL(request)
            if (b"://" in hostFull): # if http(s):// in host
                hostFull = hostFull.split(b"/")[2].decode()
            else:
                hostFull = hostFull.split(b"/")[0].decode()
        if (":" in hostFull):
            return hostFull.split(":")[0], int(hostFull.split(":")[1])
        return hostFull, 80 # incase no port default: 80

    def filterIO(self, data, rules):
        # replace data by dictionary rules
        for key, value in rules.items():
            data = re.sub(key.encode(), value.encode(), data) 
        return data

    def filterHeaderLine(self, line):
        # if line start with string on rules: delete this string
        for skipRule in self._headerRules:
            if (line.lower().startswith(skipRule)): # check lower case
                return b""
        return line

    def filterHeader(self, data):
        # drop line from header to make proxy work
        originalString = data.split(b"\r\n")
        filteredString = []
        for line in originalString:
            filteredString.append(self.filterHeaderLine(line)) # append string after filtered
        return b"\r\n".join(filteredString)

    def parseFile(self, request):
        # get file requested, use in local
        requestURL = request.split()[1].decode() # get URL
        result = "/".join(requestURL.split("/")[3:]) # spilt by "/"
        if (result == ""): # if no file requested -> index.html
            result = "index.html"
        return result

    def headerOK(self): #For future (Server, Date, Content-Type,...)
        return b'''HTTP/1.1 200 OK\r\n\r\n'''
    
    def headerNotFound(self): #For future (Server, Date, Content-Type,...)
        return b'''HTTP/1.1 404 Not Found\r\n\r\n'''

    def readFile(self, file):
        # read file from local web source
        with open(os.path.join(self._webSource, file), "rb") as f:
            data = f.read()
        return data

    def generateReplaceHTML(self, rules, returnPage):
        # auto generate replace rules (dictionary). Because this file is not permanent and can be changed by the user.
        with open(self._rulesHTML, "rb") as f:
            result = f.read()
        listRules = b"" 
        for key, value in rules.items():
            listRules += b'<li>"' + key.encode() + b'": "' + value.encode() + b'"</li>\n' # format id. "key":"value"
        result = result.replace(b"maxnumrule", str(len(rules)).encode()).replace(b"returnPage", returnPage).replace(b"listRules", listRules) # replace some tag in rules.html
        return result

    def generateListHTML(self, rules, returnPage):
        # auto generate list rules (block). Because this file is not permanent and can be changed by the user.
        with open(self._rulesHTML, "rb") as f:
            result = f.read()
        listRules = b""
        for rule in rules:
            listRules += b'<li>' + rule + b'</li>\n' # format: id. rule
        result = result.replace(b"maxnumrule", str(len(rules)).encode()).replace(b"returnPage", returnPage).replace(b"listRules", listRules) # replace some tag in rules.html
        return result

    def recvall(self, _socket, timeout = 0.001):
        # recv all data
        data = b""
        _socket.settimeout(timeout) # because browser not end TCP so we need to set timeout for _socket.recv
        try:
            while 1:
                buffer = _socket.recv(1024) # receive buffer
                if (not buffer):
                    break
                data += buffer # add buffer to data
        except: # case timeout
            pass
        return data

    def connect(self, clientSocket, clientAddress):
        request = self.recvall(clientSocket)
        if (len(request) == 0): # case bad request
            return clientSocket.close()

        addressServer, portServer = self.parseHost(request) # parse host from request
        urlServer = self.parseURL(request) # parse URL from request
        if (any([re.search(s, urlServer) for s in self._blockRules])): # check if url match any block rule
            # if matched send 404 and close
            clientSocket.sendall(self.headerNotFound())
            clientSocket.sendall(self.readFile(self._notFoundHTML))
            clientSocket.close()
        elif (addressServer != self._configServer and portServer != self._configPort): # case not config
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # tcp to server
            serverSocket.connect((addressServer, portServer))
            header, data = request.split(b"\r\n\r\n") # spilt request
            serverSocket.sendall(self.filterHeader(header) + b"\r\n\r\n" + self.filterIO(data, self._outReplaceRules)) # filter header, filter data

            try:
                data = self.recvall(serverSocket, 0.1)
                clientSocket.sendall(self.filterIO(data, self._inReplaceRules)) # filter received data, and send
                serverSocket.close() # close server
                clientSocket.close() # close client
            except Exception as e: #clientSocket close by server (user stop loading)
                serverSocket.close()
                clientSocket.close()
        else: # case config
            try:
                requestFile = self.parseFile(request) # get file browser requested
                if (requestFile == "test.html"): # only this file filter (other files in local are not)
                    data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                    data = self.filterIO(data.encode(), self._outReplaceRules).decode() # send by local so it wasnt replace so now we replace
                    if ("input=" in data):
                        data = data.split("=")[1] # get value
                    clientSocket.sendall(self.headerOK()) # response OK
                    clientSocket.sendall(self.filterIO(self.readFile(requestFile).replace(b"replacebyinput", data.encode()), self._inReplaceRules)) # sent data
                elif (os.path.isfile(os.path.join(self._webSource, requestFile))): # if have file
                    clientSocket.sendall(self.headerOK()) 
                    clientSocket.sendall(self.readFile(requestFile))
                elif (requestFile == "inReplaceRules.html"): # if modify input Replace Rules
                    if (b"newrule=" in request): # if add new rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._inReplaceRulesFile, "a") as f: 
                            f.write(data.split("=")[1] + ",\n") # append to file
                    elif (b"delete=" in request): # if delete rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._inReplaceRulesFile, "w") as f:
                            for i, (key, value) in enumerate(self._inReplaceRules.items()):
                                if (i+1 != int(data.split("=")[1])):
                                    f.write(f'"{key}":"{value}",\n') # if not line wanna delete -> write to file
                    elif (b'name="rulefile"' in request): # if upload rule
                        # parse file data
                        filedata = request.split(b"\r\n\r\n")[-1] #
                        filedata = filedata[:filedata.find(b"\r\n-----------------------------")]
                        with open(self._inReplaceRulesFile, "wb") as f: # save to file
                            f.write(filedata)

                    self._inReplaceRules = self.loadReplaceRules(self._inReplaceRulesFile) # reload

                    clientSocket.sendall(self.headerOK()) # response
                    clientSocket.sendall(self.generateReplaceHTML(self._inReplaceRules, requestFile.encode())) # sent data
                elif (requestFile == "outReplaceRules.html"): # if modify output Replace Rules
                    if (b"newrule=" in request): # if add new rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._outReplaceRulesFile, "a") as f:
                            f.write(data.split("=")[1] + ",\n") # append to file
                    elif (b"delete=" in request): # if delete rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._outReplaceRulesFile, "w") as f:
                            for i, (key, value) in enumerate(self._outReplaceRules.items()):
                                if (i+1 != int(data.split("=")[1])):
                                    f.write(f'"{key}":"{value}",\n')
                    elif (b'name="rulefile"' in request): # if upload rule
                        # parse file data
                        filedata = request.split(b"\r\n\r\n")[-1]
                        filedata = filedata[:filedata.find(b"\r\n-----------------------------")]
                        with open(self._outReplaceRulesFile, "wb") as f: # save to file
                            f.write(filedata)

                    self._outReplaceRules = self.loadReplaceRules(self._outReplaceRulesFile) # reload

                    clientSocket.sendall(self.headerOK()) # response
                    clientSocket.sendall(self.generateReplaceHTML(self._outReplaceRules, requestFile.encode())) # sent data
                elif (requestFile == "blockRules.html"):
                    if (b"newrule=" in request): # if add new rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._blockRulesFile, "a") as f:
                            f.write(data.split("=")[1] + "\n") # append to file
                    elif (b"delete=" in request): # if delete rule
                        data = unquote(request.split(b"\r\n\r\n")[-1].decode().replace("+", " ")) # get input from user
                        with open(self._blockRulesFile, "wb") as f:
                            for i, rule in enumerate(self._blockRules):
                                if (i+1 != int(data.split("=")[1])):
                                    f.write(rule + b'\n') # if not line wanna delete -> write to file
                    elif (b'name="rulefile"' in request): # if upload rule
                        # parse file data
                        filedata = request.split(b"\r\n\r\n")[-1]
                        filedata = filedata[:filedata.find(b"\r\n-----------------------------")]
                        with open(self._blockRulesFile, "wb") as f: # save to file
                            f.write(filedata)

                    self._blockRules = self.loadListRules(self._blockRulesFile) # reload

                    clientSocket.sendall(self.headerOK()) # response
                    clientSocket.sendall(self.generateListHTML(self._blockRules, requestFile.encode())) # sent data
                else: # case file requested not existe
                    clientSocket.sendall(self.headerNotFound())
                    clientSocket.sendall(self.readFile(self._notFoundHTML))
                clientSocket.close()
            except Exception as e: #clientSocket close by server (user stop loading)
                print(e)
                clientSocket.close()

# create proxy   
proxyServer = ProxyServer(port = 12345, 
                          headerRulesFile = "headerRules.txt",
                          inReplaceRulesFile = "inReplaceRules.txt",
                          outReplaceRulesFile = "outReplaceRules.txt",
                          blockRulesFile = "blockRules.txt",
                          rulesHTML = "rules.html",
                          notFoundHTML = "404.html", 
                          webSource = "web/",
                          configServer = "myproxy.com",
                          configPort = 1234)
proxyServer.start() # start