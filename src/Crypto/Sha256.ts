const forge = require("./CustomForge");
import Logger from "../Helpers/Logger";

const forgeSha256 = forge.sha256;
const forgeUtil = forge.util;

/**
 * Hashes a string using sha256
 * @param {string} string
 * @returns {Promise<string>}
 */
export const stringToHash = async (string: string) => {
    const messageDigest = forgeSha256.create();
    messageDigest.update(string);
    return messageDigest.digest().toHex();
};

/**
 * Encrypts a string using a publicKey
 * @param {string} data
 * @param publicKey
 * @returns {Promise<string>}
 */
export const encryptString = async (data: string, publicKey: any) => {
    // create a new message digest for our string
    const messageDigest = forgeSha256.create();
    messageDigest.update(data, "utf8");

    // sign it with a private key
    const signatureBytes = publicKey.encrypt(messageDigest);
    // encode to base 64 and return it
    return forgeUtil.encode64(signatureBytes);
};

/**
 * Signs a string using a privateKey
 * @param {string} data
 * @param privateKey
 * @returns {Promise<string>}
 */
export const signString = async (data: string, privateKey: any) => {
    // create a new message digest for our string
    const messageDigest = forgeSha256.create();
    messageDigest.update(data, "utf8");

    // sign it with a private key
    const signatureBytes = privateKey.sign(messageDigest);
    // encode to base 64 and return it
    return forgeUtil.encode64(signatureBytes);
};

/**
 * Verifies if a string was signed by a public key
 * @param {string} data
 * @param publicKey
 * @param {string} signature
 * @returns {Promise<string>}
 */
export const verifyString = async (
    data: string,
    publicKey: any,
    signature: string
) => {
    // create a new message digest for our string
    const messageDigest = forgeSha256.create();
    messageDigest.update(data, "utf8");

    console.log(data.length, publicKey, signature);

    // decode the base64 signature
    const rawSignature = forgeUtil.decode64(signature);
    const nodeBuffer = Buffer.from(signature, "base64");
    const forgeBuffer = forge.util.createBuffer(rawSignature);
    const forgeBuffer2 = forge.util.createBuffer(Buffer.from(signature, "base64"));
    console.log("rawSignature", rawSignature, typeof rawSignature);
    console.log("==========");
    console.log("nodeBuffer", nodeBuffer, typeof nodeBuffer);
    console.log("==========");
    console.log("forgeBuffer_", forgeBuffer, typeof forgeBuffer);
    console.log("==========");
    console.log("forgeBuffer2", forgeBuffer2, typeof forgeBuffer2);

    try {
        console.log("rawSignature with default scheme");
        let result1 = publicKey.verify(messageDigest, rawSignature);
        console.log(result1);
    } catch (ex) {
        Logger.error(ex);
    }

    try {
        console.log("nodeBuffer with default scheme");
        let result12 = publicKey.verify(messageDigest, nodeBuffer);
        console.log(result12);
    } catch (ex) {
        Logger.error(ex);
    }

    try {
        console.log("forgeBuffer with default scheme");
        let result2 = publicKey.verify(messageDigest, forgeBuffer);
        console.log(result2);
    } catch (ex) {
        Logger.error(ex);
    }

    try {
        console.log("forgeBuffer2 with default scheme");
        let result3 = publicKey.verify(messageDigest, forgeBuffer2);
        console.log(result3);
    } catch (ex) {
        Logger.error(ex);
    }

    return false;
};
