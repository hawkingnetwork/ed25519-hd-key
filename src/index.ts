var CryptoJS = require("crypto-js");
const Sodium = require('react-native-sodium').default;

import { replaceDerive, pathRegex } from './utils';

type Hex = string;
type Path = string;

type Keys = {
    key: Buffer;
    chainCode: Buffer;
};

const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;


export const getMasterKeyFromSeed = (seed: Hex): Keys => {
    const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, ED25519_CURVE);
    const I = Buffer.from(hmac.update(Buffer.from(seed, 'hex')).finalize().toString());
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

const CKDPriv = ({ key, chainCode }: Keys, index: number): Keys => {
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

export const getPublicKey = async (privateKey: Buffer, withZeroByte = true): Promise<Buffer> => {
    const { pk } = await Sodium.crypto_sign_seed_keypair(privateKey.toString('base64'));
    const signPk = new Buffer(pk, 'base64');
    const zero = Buffer.alloc(1, 0);
    return withZeroByte ?
        Buffer.concat([zero, Buffer.from(signPk)]) :
        Buffer.from(signPk);
};

export const isValidPath = (path: string): boolean => {
    if (!pathRegex.test(path)) {
        return false;
    }
    return !path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .some(isNaN as any /* ts T_T*/);
};

export const derivePath = (path: Path, seed: Hex): Keys => {
    if (!isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }

    const { key, chainCode } = getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .map(el => parseInt(el, 10));

    return segments.reduce(
        (parentKeys, segment) => CKDPriv(parentKeys, segment + HARDENED_OFFSET),
        { key, chainCode },
    );
};
