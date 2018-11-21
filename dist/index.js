"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
var CryptoJS = require("crypto-js");
const Sodium = require('react-native-sodium').default;
const utils_1 = require("./utils");
const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;
exports.getMasterKeyFromSeed = (seed) => {
    const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, ED25519_CURVE);
    const I = Buffer.from(hmac.update(Buffer.from(seed, 'hex')).finalize().toString());
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};
const CKDPriv = ({ key, chainCode }, index) => {
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);
    const I = Buffer.from(CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, chainCode.toString())
        .update(data)
        .finalize().toString());
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};
exports.getPublicKey = (privateKey, withZeroByte = true) => __awaiter(this, void 0, void 0, function* () {
    const { pk } = yield Sodium.crypto_sign_seed_keypair(privateKey.toString('base64'));
    const signPk = new Buffer(pk, 'base64');
    const zero = Buffer.alloc(1, 0);
    return withZeroByte ?
        Buffer.concat([zero, Buffer.from(signPk)]) :
        Buffer.from(signPk);
});
exports.isValidPath = (path) => {
    if (!utils_1.pathRegex.test(path)) {
        return false;
    }
    return !path
        .split('/')
        .slice(1)
        .map(utils_1.replaceDerive)
        .some(isNaN);
};
exports.derivePath = (path, seed) => {
    if (!exports.isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }
    const { key, chainCode } = exports.getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(utils_1.replaceDerive)
        .map(el => parseInt(el, 10));
    return segments.reduce((parentKeys, segment) => CKDPriv(parentKeys, segment + HARDENED_OFFSET), { key, chainCode });
};
