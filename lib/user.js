'use strict';

const nedb = require(`nedb`);
const bluebird = require(`bluebird`);
const bcrypt = require(`bcrypt`);
const path = require(`path`);
const crypto = require(`crypto`);

const userData = bluebird.promisifyAll(new nedb({filename: path.join(__dirname, `../`, `data`, `users.db`), autoload: true}));

class user {
    constructor() {
        this.userData = userData;
    }

    register(username, password) {
        return this.userData.findOneAsync({username}).then((user) => {
            if (user) {
                return bluebird.reject(`Username ${username} already exists`);
            }

            return bcrypt.hash(password, 10);
        }).then((hash) => {
            return this.userData.insertAsync({
                username,
                password: hash,
                tokens: []
            });
        });
    }

    authenticate(username, password) {
        return this.userData.findOneAsync({username}).then((userDoc) => {
            if (!userDoc) {
                return bluebird.reject();
            }

            return bcrypt.compare(password, userDoc.password);
        }).then((matched) => {
            if (!matched) {
                return bluebird.reject();
            }

            return this.generateToken(username);
        }).catch(() => {
            return bluebird.reject(`Incorrect account details`)
        });
    }

    verifyToken(token) {
        return this.userData.findOneAsync({tokens: {$elemMatch: token}}).then((userDoc) => {
            if (userDoc) {
                return bluebird.resolve(true);
            }

            return bluebird.reject('Invalid token');
        });
    }

    generateToken(username) {
        const hash = crypto.createHash(`sha256`);

        hash.update(username + Date.now());

        const token = hash.digest(`hex`);

        return this.userData.updateAsync({username}, {$push: {tokens: token}}).then(() => {
            return token;
        });
    }
}

module.exports = user;
