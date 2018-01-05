'use strict';

let usage=`Javascript SSL
js-ssl server <tls-version> <certificateFile.pem,...> <keyFile.pem> <listen [host:]port>
js-ssl client <tls-version> <connect [host:]port>
js-ssl httpsClient <tls-version> <method> <url>
js-ssl proxy <tls-version> <listen [host:]port> <connect [host:]port>
js-ssl httpProxy <tls-version> <listen [host:]port>

where tls-version is ssl3 or tls1.0
`;

const net = require('net');
const fs = require('fs');
const url = require('url');
const {sslConnect,sslServer} = require('./streams');
const {ProtocolVersion} = require('./protocol');
const Agent = require('./agent');
const https = require('https');
const http = require('http');

function parseAddress(specification) {
    if (!specification.includes(':')) return {port:parseInt(specification)};
    let [host,port] = specification.split(':');
    return {host,port:parseInt(port)};
}

function server(versionSpecification,certificateFileList, keyFile, listenSpecification) {
    let certificates=certificateFileList.split(',').map(name=>fs.readFileSync(name));
    let key=fs.readFileSync(keyFile);
    let server=sslServer(ProtocolVersion.parse(versionSpecification),certificates, key,(socket)=>{
        socket.pipe(socket);
        // socket.pipe(process.stdout);
        // socket.write('Hello!');
        // socket.end();
    });
    server.listen(parseAddress(listenSpecification));
}

function client(versionSpecification, connectSpecification) {
    let socket=sslConnect(ProtocolVersion.parse(versionSpecification),parseAddress(connectSpecification));
    //socket.on('end',()=>process.stdin.destroy());
    socket.pipe(process.stdout);
    process.stdin.pipe(socket);
    //process.stdin.on('data',data=>console.log(data));
}

function proxy(versionSpecification, listenSpecification, connectSpecification) {
    let server=net.createServer(connection=>{
        let remoteConnection=sslConnect(ProtocolVersion.parse(versionSpecification),parseAddress(connectSpecification));
        connection.pipe(remoteConnection);
        remoteConnection.pipe(connection);
    }).listen(parseAddress(listenSpecification));
}



function httpsClient(versionSpecification, method, requestUrl) {
    let agent = new Agent(ProtocolVersion.parse(versionSpecification));
    console.log({method, agent, ...url.parse(requestUrl)});
    let clientRequest = https.request(
        {method, agent, ...url.parse(requestUrl)},
        (response)=>{
            console.log(clientRequest.statusCode);
            console.log();
            response.pipe(process.stdout)
        }
    );
    clientRequest.end();

}

function httpProxy(versionSpecification, listenSpecification) {
    let agent = new Agent(ProtocolVersion.parse(versionSpecification));
    let server=http.createServer((req,res)=>{
        console.log(req.url,req.rawHeaders);
        let clientRequest = https.request(
            {method:req.method, agent, ...url.parse(req.url), protocol:'https:'},
            (response)=>{
                console.log(response.statusCode);
                let headers=response.headers;
                if (headers.location) headers.location=headers.location.replace(/^https:/,"http:");
                res.writeHead(response.statusCode, headers);
                response.pipe(res)
            }
        );
        clientRequest.end();
    }).listen(parseAddress(listenSpecification));
    server.on('connect',(request, socket, head)=>{
        console.log('connect:',request.headers,head.length);
    });
}

function help() {
    console.log(usage);
}

function main(args) {
    (({server, client, proxy, httpProxy, httpsClient})[args[0]] || help)(...args.slice(1));
}

module.exports={main};
