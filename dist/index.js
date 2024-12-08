"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateUrl = exports.generateUrl = void 0;
const crypto = __importStar(require("crypto"));
const secretKey = crypto.createHash('sha256').update('your-encryption-key').digest().slice(0, 32);
const algorithm = 'aes-256-cbc';
const isValidUrl = (url) => /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/]*)?$/.test(url);
function generateUrl(url, expiry) {
    if (!isValidUrl(url)) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid URL or URL includes query parameters");
        return url;
    }
    if (validateOption(expiry)) {
        let expiresIn = 1;
        if (expiry.days)
            expiresIn = expiry.days * 24 * 60 * 60 * 1000;
        if (expiry.hours)
            expiresIn += expiry.hours * 60 * 60 * 1000;
        if (expiry.minutes)
            expiresIn += expiry.minutes * 60 * 1000;
        if (expiry.seconds)
            expiresIn += expiry.seconds * 1000;
        expiresIn += Date.now();
        return `${url}?urlExpiresToken=${encryptPayload({ url, expiresIn })}`;
    }
    return url;
}
exports.generateUrl = generateUrl;
function validateUrl(url) {
    var _a;
    const query = url.split("?");
    const token = (_a = query[1]) === null || _a === void 0 ? void 0 : _a.split("=")[1];
    if (!isValidUrl(query[0]) || !token) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid URL or Token not found");
        return false;
    }
    const payload = decryptPayload(token);
    if (!payload) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid Token");
        return false;
    }
    if (Date.now() > payload.expiresIn) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Token Expired");
        return false;
    }
    return true;
}
exports.validateUrl = validateUrl;
const url = generateUrl("https://avshops.shop", { seconds: 1 });
setTimeout(() => console.log(validateUrl(url)), 2000);
function validateOption(options) {
    const values = Object.values(options);
    if (values.length < 1 || !values.every(item => item > 0)) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Please setup a expiry more than 0");
        return false;
    }
    return true;
}
function encryptPayload(payload) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}-${encrypted}`;
}
function decryptPayload(token) {
    const [ivHex, encrypted] = token.split('-');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}
