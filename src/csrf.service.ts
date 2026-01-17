import { Injectable } from "@nestjs/common";
import { randomBytes,timingSafeEqual } from "node:crypto";
import { CSRF_DEFAULT_TOKEN_LENGTH } from "./constants";
import { CSRFToken, CSRFTokenPayload } from "./interfaces/csrf-token.interface"
import { InvalidTokenError } from "./errors/invalid-token.error";
import { CSRFTokenImplemention } from "./CSRFTokenImpls.class";

@Injectable()
export class CsrfService {
    private readonly tokenLength:number;
    private readonly TOKEN_TIME_ALIVE = 60;
    private readonly START_USES = 0;

    /**
     * Constructor for CsrfService 
     * @param tokenLength length of the csrf, the default is the specified in 
     */
    constructor(tokenLength:number = CSRF_DEFAULT_TOKEN_LENGTH){
        this.tokenLength = tokenLength;
    }

    /**
     * Generetes a csrf token with crypto
     * @returns a random csrf token
     */
    generateToken():string {
        let tokenID = randomBytes(this.tokenLength).toString('base64url');
        let releaseDate = new Date();
        let expirationDate = new Date(releaseDate.getTime() + this.TOKEN_TIME_ALIVE);
        let numUses = this.START_USES;
        
        const payload:CSRFTokenPayload = {
            tokenID,
            releaseDate,
            expirationDate,
            numUses
        }

        return Buffer.from(JSON.stringify(payload)).toString('base64url')
    }

    /**
     * Validates cookie from header and the token
     * @param cookieToken string with the csrf token present in the cookie
     * @param headerToken string with the csrf token present in the header
     * @returns true if the csrf token is valid
     * @returns false otherwise
     */
    validateToken(cookieToken:string, headerToken:string):Boolean{
        if (!cookieToken || !headerToken)
            return false;
    
        if (cookieToken.length !== headerToken.length)
            return false;

        try {
            const cookieBuffer:Buffer<ArrayBuffer> = Buffer.from(cookieToken);
            const headerBuffer:Buffer<ArrayBuffer> = Buffer.from(headerToken);

            return timingSafeEqual(cookieBuffer,headerBuffer);
        } catch (error:any){
            return false;
        }
    }

    /**
     * Decodes a token to return it's value
     * @param token to be decoded
     * @returns a CSRFToken with all it's properties
     * @throws InvalidTokenError exception if not a valid CSRFTokenPayload
     */
    decodeToken(token:string):CSRFToken{
        let payloadStringify = Buffer.from(token,"base64url").toString("binary")
        let payload:CSRFTokenPayload = JSON.parse(payloadStringify);

        if (!("tokenID" in payload))
            throw new InvalidTokenError("No tokenID present in payload")
        if (!("releaseDate" in payload))
            throw new InvalidTokenError("No releaseDate present in payload")
        if (!("expirationDate" in payload))
            throw new InvalidTokenError("No expirationDate present in payload")
        if (!("numUses" in payload))
            throw new InvalidTokenError("No numUses present in payload")

        return new CSRFTokenImplemention(payload.tokenID.toString(),
            new Date(payload.releaseDate),
            new Date(payload.expirationDate),
            payload.numUses.valueOf());
    }

    useToken(token:string):string{
        let csrf = this.decodeToken(token);
        csrf.setNumUses(csrf.numUses + 1);
        return csrf.convertToken();
    }

}