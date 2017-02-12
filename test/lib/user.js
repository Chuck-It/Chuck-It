'use strict';

const nedb = require(`nedb`);
const bluebird = require(`bluebird`);
const path = require(`path`);
const bcrypt = require(`bcrypt`);
const crypto = require(`crypto`);
const sinon = require(`sinon`);
const chai = require(`chai`);
const chaiAsPromised = require(`chai-as-promised`);

chai.use(chaiAsPromised);

const expect = chai.expect;

const userModule = require(path.join(`..`, `..`, `lib`, `user.js`));

describe(`User`, function() {
    let user;
    let sandbox = sinon.sandbox.create();
    beforeEach(function() {
        user = new userModule();
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe(`#register()`, function() {
        it(`should reject if the user already exists`, function() {
            sandbox.stub(user.userData, 'findOneAsync', function() {
                return bluebird.resolve({username: 'test'});
            });

            const userPromise = user.register('test', 'password');

            return expect(userPromise).to.be.rejectedWith(`Username test already exists`);
        });

        it(`should resolve with a user object`, function() {
            sandbox.stub(user.userData, 'insertAsync', function(userObject) {
                return bluebird.resolve(userObject);
            });

            const userPromise = user.register('test', 'password');

            return expect(userPromise).to.eventually.have.deep.property('username', 'test');
        });
    });

    describe(`#authenticate()`, function(){
        it(`should reject if the user does not exist`, function() {
            sandbox.stub(user.userData, 'findOneAsync', function() {
                return bluebird.resolve();
            });

            const userPromise = user.authenticate('test', 'password');

            return expect(userPromise).to.be.rejectedWith(`Incorrect account details`);
        });

        it(`should reject if the password does not match`, function() {
            sandbox.stub(user.userData, 'findOneAsync', function() {
                return bluebird.resolve({username: 'test', password: 'wrong'});
            });

            const userPromise = user.authenticate('test', 'password');

            return expect(userPromise).to.be.rejectedWith(`Incorrect account details`);
        });

         it(`should resolve if authentication is successful`, function() {
            return bcrypt.hash(`password`, 10).then((password) => {
                sandbox.stub(user.userData, 'findOneAsync', function() {
                    return bluebird.resolve({username: 'test', password});
                });

                sandbox.stub(user, 'generateToken', function() {
                    return bluebird.resolve(12345);
                });

                const userPromise = user.authenticate('test', 'password');

                return expect(userPromise).to.eventually.equal(12345);
            });
        });
    });

    describe(`#verifyToken()`, function(){
        it(`should reject if the token is invalid`, function() {
            sandbox.stub(user.userData, 'findOneAsync', function() {
                return bluebird.resolve();
            });

            const userPromise = user.verifyToken('invalid-token');

            return expect(userPromise).to.be.rejectedWith(`Invalid token`);
        });

        it(`should resolve if the token is valid`, function() {
            sandbox.stub(user.userData, 'findOneAsync', function() {
                return bluebird.resolve({username: 'test'});
            });

            const userPromise = user.verifyToken('12345');

            return expect(userPromise).to.eventually.be.true;
        });
    });

    describe(`#generateToken()`, function(){
        it(`should return a token for the user`, function() {
            sandbox.stub(user.userData, 'updateAsync', function() {
                return bluebird.resolve();
            });

            const date = Date.now();

            sandbox.useFakeTimers(date);

            const hash = crypto.createHash(`sha256`);

            hash.update(`test` + date);

            const token = hash.digest(`hex`);

            const userPromise = user.generateToken(`test`);

            return expect(userPromise).to.eventually.equal(token);
        });
    });
});
