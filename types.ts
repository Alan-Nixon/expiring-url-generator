export type ExpiryType = {
    days?: number;
    hours?: number;
    minutes?: number;
    seconds?: number;
}

export type TypePayload = {
    url: string;
    expiresIn: number;
}