let https = require('https');
const {sslConnect} = require('./streams');

module.exports = class Agent extends https.Agent {
    constructor(version) {
        super();
        this.version=version;
    }

    createConnection(options) {
        return sslConnect(this.version,options);
    }
}
