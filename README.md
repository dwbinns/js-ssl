# Native JavaScript SSL/TLS #

A native JavaScript implementation of SSL3.0 and TLS1.0. Uses Node's OpenSSL for cryptography. Unlikely to be secure, intended for protocol experimentation.

## Installation ##

```
npm install js-ssl
```

## Command-line usage ##

For usage, run:
```
npm js-ssl
```
for example:
```
npx js-ssl httpsClient tls1.0 GET https://www.google.com
```

## Code usage ##

For example:
```
const {sslConnect, ProtocolVersion} = require('js-ssl');

let connection = sslConnect(ProtocolVersion.TLS1_0, {host: 'www.google.com', port: 443});

connection.write('GET / HTTP/1.0\r\n\r\n');
connection.pipe(process.stdout);
```

## API ##

### sslConnect(protocolVersion, connectOptions) ###
Connect with ssl to the specified location.

** parameters **
- protocolVersion `ProtocolVersion` - Specify protocol version `ProtocolVersion.TLS1_0` or  `ProtocolVersion.SSL3`
- connectOptions `Object` - passed to net.connect, so typically something like: {host: 'my.host.name', port: 443}
