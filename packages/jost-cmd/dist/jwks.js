"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
class Jwks {
    constructor() {
        this.keys = [];
    }
    addKey(key) {
        this.keys.unshift(key);
    }
    // getUniqueKeyId() {
    //   let i = 1
    //   while (this.keys.some((key) => key.kid === `key${i}`)) {
    //     ++i
    //   }
    //   return `key${i}`
    // }
    async write(output) {
        const json = JSON.stringify(this, null, '  ') + '\n';
        await new Promise((resolve, reject) => {
            output.write(json, 'utf8', (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
    async writeToFile(path) {
        const output = (0, fs_1.createWriteStream)(path);
        await this.write(output);
        await new Promise((resolve, reject) => {
            output.end(resolve);
        });
    }
    static fromFile(path) {
        const json = (0, fs_1.readFileSync)(path, { encoding: 'utf-8' });
        const obj = JSON.parse(json);
        const jwks = new Jwks();
        Object.assign(jwks, obj);
        if (!Array.isArray(jwks.keys))
            jwks.keys = [];
        return jwks;
    }
}
exports.default = Jwks;
//# sourceMappingURL=jwks.js.map