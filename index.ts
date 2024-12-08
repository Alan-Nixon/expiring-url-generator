import * as crypto from 'crypto';
import { ExpiryType, TypePayload } from './types';

const secretKey = crypto.createHash('sha256').update('your-encryption-key').digest().slice(0, 32);
const algorithm = 'aes-256-cbc';

const isValidUrl = (url: string) => /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/]*)?$/.test(url);

export function generateUrl(url: string, expiry: ExpiryType) {
    if (!isValidUrl(url)) { console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid URL or URL includes query parameters"); return url }
    if (validateOption(expiry)) {
        let expiresIn = 1
        if (expiry.days) expiresIn = expiry.days * 24 * 60 * 60 * 1000
        if (expiry.hours) expiresIn += expiry.hours * 60 * 60 * 1000
        if (expiry.minutes) expiresIn += expiry.minutes * 60 * 1000
        if (expiry.seconds) expiresIn += expiry.seconds * 1000
        expiresIn += Date.now()
        return `${url}?urlExpiresToken=${encryptPayload({ url, expiresIn })}`
    }
    return url
}

export function validateUrl(url: string) {
    const query = url.split("?")
    const token = query[1]?.split("=")[1]
    if (!isValidUrl(query[0]) || !token) { console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid URL or Token not found"); return false }
    const payload = decryptPayload(token)
    if (!payload) { console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Invalid Token"); return false }
    if (Date.now() > payload.expiresIn) { console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Token Expired"); return false }
    return true
}

const url = generateUrl("https://avshops.shop", { seconds: 1 })
setTimeout(() => console.log(validateUrl(url)), 2000)

function validateOption(options: ExpiryType) {
    const values = Object.values(options);
    if (values.length < 1 || !values.every(item => item > 0)) {
        console.log("\x1b[1m\x1b[31m%s\x1b[0m", "Please setup a expiry more than 0");
        return false
    }
    return true
}

function encryptPayload(payload: TypePayload): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}-${encrypted}`;
}

function decryptPayload(token: string): TypePayload {
    const [ivHex, encrypted] = token.split('-');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}