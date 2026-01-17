export interface CSRFToken {
    tokenID: string,
    releaseDate: Date,
    expirationDate: Date,
    readonly numUses:number,
    setNumUses(arg1:number):void,
    isTokenValid():boolean
}

export type CSRFTokenPayload = {
    tokenID: String,
    releaseDate: Date,
    expirationDate: Date,
    numUses: Number
}