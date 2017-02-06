'use strict';

const nedb = require(`nedb`);
const bluebird = require(`bluebird`);
const bcrypt = require(`bcrypt`);
const path = require(`path`);

const userData = bluebird.promisifyAll(new nedb({path: path.join(__dirname, `data`, `users.db`), autoload: true}));

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
                password: hash
            });
        });
    }

    authenticate(username, password) {
        return this.userData.findOneAsync({username}).then((user) => {
            if (!user) {
                return bluebird.reject();
            }

            return  bcrypt.compare(password, user.password);
        }).then((matched) => {
            if (!matched) {
                return bluebird.reject();
            }

            return bluebird.resolve(true);
        }).catch(() => {
            return bluebird.reject(`Incorrect account details`)
        });
    }
}

module.exports = user;
