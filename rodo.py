# Author: https://zhgchg.li
# Githup Repo: https://github.com/ZhgChgLi/mitmproxy-rodo
# License: MIT
# Created at: 2023/09/04

import re
import logging
import mimetypes
import os
import json
import hashlib
import shutil
import fnmatch
import datetime
import pickle

from pathlib import Path
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import flowfilter
from mitmproxy.http import Headers

class RodoHandler:
    def load(self, loader):
        self.filter = ctx.options.dumper_filter
        self.readHistory = {}
        self.configuration = {}
        self.cleanIfRecordAtFirstLaunch = True

        loader.add_option(
            name="dumper_folder",
            typespec=str,
            default="dump",
            help="Response Dump directory, can be created by Test Case Name",
        )

        loader.add_option(
            name="network_restricted",
            typespec=bool,
            default=True,
            help="No local mapping data... Set true to return 404, false to make real requests to fetch data.",
        )

        loader.add_option(
            name="record",
            typespec=bool,
            default=False,
            help="Set true to record Request's Response.",
        )

        loader.add_option(
            name="auto_extend_cookie_expire_days",
            typespec=int,
            default=7,
            help="Specifies the number of days to automatically extend all cookie expires if the max-age is not set. Set to 0 to disable auto ",
        )

        loader.add_option(
            name="config_file",
            typespec=str,
            default="",
            help="Path to the config.js configuration file.",
        )

    def configure(self, updated):       
        if "dumper_filter" in updated:
            self.filter = ctx.options.dumper_filter
        self.loadConfig()
        

    def loadConfig(self):
        configFile = Path(ctx.options.config_file)
        if ctx.options.config_file == "" or not configFile.exists():
            return

        self.configuration = json.loads(open(configFile, "r").read())

    def rule(self, request):
        host = request.host
        requestPath = "-".join(request.path_components)
        method = request.method
        
        ignoredConfiguration = self.configuration.get("ignored", {})

        iterable = False
        query = []
        formData = []
        
        matchHost = {key: value for key, value in sorted(ignoredConfiguration.items(), key=lambda item: len(item[0])) if fnmatch.fnmatch(host, key)}
        for matchHostKey, matchHostValue in matchHost.items():
            matchRequestPath = {key: value for key, value in sorted(matchHostValue.items(), key=lambda item: len(item[0])) if fnmatch.fnmatch(requestPath, key)}
            for matchRequestPathKey, matchRequestPathValue in matchRequestPath.items():
                matchMethod = {key: value for key, value in sorted(matchRequestPathValue.items(), key=lambda item: len(item[0])) if fnmatch.fnmatch(method, key)}
                for matchMethodKey, matchMethodValue in matchMethod.items():
                    if matchMethodValue.get("iterable"):
                        iterable = matchMethodValue.get("iterable")
                    enables = []
                    if matchMethodValue.get("enables"):
                        for enable in matchMethodValue.get("enables"):
                            enables.append(enable)
                    
                    if "query" in enables:
                        if matchMethodValue.get("rules") and matchMethodValue.get("rules").get("query") and matchMethodValue.get("rules").get("query").get("parameters"):
                            for parameter in matchMethodValue.get("rules").get("query").get("parameters"):
                                if query == None:
                                    query = []
                                query.append(parameter)
                    else:
                        query = None

                    if "formData" in enables:
                        if matchMethodValue.get("rules") and matchMethodValue.get("rules").get("query") and matchMethodValue.get("rules").get("formData").get("parameters"):
                            for parameter in matchMethodValue.get("rules").get("formData").get("parameters"):
                                if formData == None:
                                    formData = []
                                formData.append(parameter)
                    else:
                        formData = None
        
        return {"iterable":iterable, "query":query, "formData":formData}
    
    def parseFormData(self, request):
        formData = []
        if len(request.urlencoded_form) > 0:
            formData = request.urlencoded_form
        elif request.get_content() != None and request.get_content() != b'':
            try:
                formData = json.loads(request.get_content())
            except Exception:
                formData = []

        return formData

    def hash(self, request):
        rule = self.rule(request)

        query = request.query
        
        filteredQuery = []
        if query and rule.get('query') != None:
            filteredQuery = [(key, value) for key, value in query.items() if key not in rule["query"]]
        
        formData = self.parseFormData(request)

        filteredFormData = []
        if formData and rule.get('formData') != None:
            filteredFormData = [(key, value) for key, value in formData.items() if key not in rule["formData"]]

        # Serialize the dictionary to a JSON string
        hashData = {"query":sorted(filteredQuery), "form": sorted(filteredFormData)}
        json_str = json.dumps(hashData, sort_keys=True)

        # Apply SHA-256 hash function
        hash_object = hashlib.sha256(json_str.encode())
        hash_string = hash_object.hexdigest()

        return hash_string

    def readFromFile(self, request):
        host = request.host
        method = request.method
        hash = self.hash(request)
        requestPath = "-".join(request.path_components)

        folder = Path(ctx.options.dumper_folder) / host / requestPath / method / hash

        if not folder.exists():
            return None

        content_type = request.headers.get("content-type", "").split(";")[0]
        ext = mimetypes.guess_extension(content_type) or ".json"


        count = self.readHistory.get(host, {}).get(method, {}).get(requestPath, {}).get(hash, 0)

        filepath = folder / f"Content-{str(count)}{ext}"

        while not filepath.exists() and count > 0:
            count = count - 1
            filepath = folder / f"Content-{str(count)}{ext}"

        if self.readHistory.get(host) is None:
            self.readHistory[host] = {}
        if self.readHistory.get(host).get(method) is None:
            self.readHistory[host][method] = {}
        if self.readHistory.get(host).get(method).get(requestPath) is None:
            self.readHistory[host][method][requestPath] = {}

        if filepath.exists():
            headerFilePath = folder / f"Header-{str(count)}.json"
            if not headerFilePath.exists():
                headerFilePath = None
            count += 1
            self.readHistory[host][method][requestPath][hash] = count

            return {"content": filepath, "header": headerFilePath}
        else:
            return None


    def saveToFile(self, request, response):
        host = request.host
        method = request.method
        hash = self.hash(request)
        requestPath = "-".join(request.path_components)

        iterable = self.configuration.get("ignored", {}).get("paths", {}).get(request.host, {}).get(requestPath, {}).get(request.method, {}).get("iterable", False)
        
        folder = Path(ctx.options.dumper_folder) / host / requestPath / method / hash

        # create dir if not exists
        if not folder.exists():
            os.makedirs(folder)

        content_type = response.headers.get("content-type", "").split(";")[0]
        ext = mimetypes.guess_extension(content_type) or ".json"

        repeatNumber = 0
        filepath = folder / f"Content-{str(repeatNumber)}{ext}"
        while filepath.exists() and iterable == False:
            repeatNumber += 1
            filepath = folder / f"Content-{str(repeatNumber)}{ext}"
        
        # dump to file
        with open(filepath, "wb") as f:
            f.write(response.content or b'')
            
        
        headerFilepath = folder / f"Header-{str(repeatNumber)}.json"
        with open(headerFilepath, "wb") as f:
            headerData = {}
            response.headers['_status_code'] = str(response.status_code)
            for field in response.headers.fields:
                key = field[0]
                value = field[1]
                current = headerData.get(key, [])
                current.append(value)
                headerData[key] = current
            pickle.dump(headerData, f)

        return {"content": filepath, "header": headerFilepath}

    def request(self, flow):
        if not flowfilter.match(self.filter, flow):
            return
        
        if self.cleanIfRecordAtFirstLaunch == True:
            if ctx.options.record == True:
                dump_folder = Path(ctx.options.dumper_folder)
                if os.path.exists(dump_folder) and os.path.isdir(dump_folder):
                    # Folder exists, delete it and its contents
                    shutil.rmtree(dump_folder) 
            self.cleanIfRecordAtFirstLaunch = False
        
        if ctx.options.record != True:
            host = flow.request.host
            path = flow.request.path

            result = self.readFromFile(flow.request)
            if result is not None:
                content = b''
                headers = []
                statusCode = 200

                if result.get('content') is not None:
                    content = open(result['content'], "r").read()

                if result.get('header') is not None:
                    with open(result['header'], "rb") as f:
                        objs = pickle.load(f)
                        for key in objs:
                            for value in objs[key]:
                                if key == "_status_code":
                                    statusCode = value
                                else:
                                    headers.append((key, value))

                headers.append((b'_responseFromMitmproxy', b'1'))
                
                headersObj = Headers(headers)
                self.extendSetCookieExpires(headersObj)
                flow.response = http.Response.make(statusCode, content, headersObj)
                logging.info("Fullfill response from local with "+str(result['content']))
                return

            if ctx.options.network_restricted == True:
                flow.response = http.Response.make(404, b'', Headers([(b'_responseFromMitmproxy', b'1')]))
    
    def extendSetCookieExpires(self, headersObj):
        if ctx.options.auto_extend_cookie_expire_days <= 0:
            return
        
        cookies = headersObj.get_all('set-cookie')
        for index, cookie in enumerate(cookies):
            newExpiresDate = datetime.datetime.utcnow() + datetime.timedelta(days=ctx.options.auto_extend_cookie_expire_days)
            maxAgeMatch = re.search(r'Max-Age=([^;]+)', cookie)
            if maxAgeMatch:
                maxAge = int(maxAgeMatch.group(1))
                if maxAge > 0:
                    newExpiresDate = datetime.datetime.utcnow() + datetime.timedelta(seconds=maxAge)
            
            newExpires = newExpiresDate.strftime("%a, %d %b %Y %H:%M:%S GMT")
            newCookie = re.sub(r'expires=([^;]+)', newExpires, cookie)
            cookies[index] = newCookie
        headersObj.set_all("Set-Cookie", cookies)

    def response(self, flow):
        if not flowfilter.match(self.filter, flow):
            return
        
        # Handle Set-Cookie Operation in reverse proxy mode
        if flow.client_conn.proxy_mode.type_name == "reverse":
            setCookies = flow.response.headers.get_all("set-cookie")
            host = flow.client_conn.proxy_mode.address[0]
            hostName = re.sub(r'\.', r'\\.', '.'.join(host.split('.')[-2:]))
            setCookies = [re.sub(r"\s*\."+hostName+"\s*", "127.0.0.1", s) for s in setCookies]
            flow.response.headers.set_all("Set-Cookie", setCookies)
        
        if ctx.options.record == True and flow.response.headers.get('_responseFromMitmproxy') != '1':
            result = self.saveToFile(flow.request, flow.response)
            logging.info("Save response to local with "+str(result['content']))

addons = [RodoHandler()]