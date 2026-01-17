import { MAX_USES } from "./constants";
import { InvalidTokenError } from "./errors/invalid-token.error";
import { MaxUsesError } from "./errors/max-uses.error";
import { CSRFToken, CSRFTokenPayload } from "./interfaces/csrf-token.interface";

export class CSRFTokenImplemention implements CSRFToken{
    readonly tokenID: string;
    readonly releaseDate: Date;
    readonly expirationDate: Date;
    numUses!: number;

    constructor(tokenID:string, releaseDate:Date, expirationDate:Date, numUses:number){
        this.tokenID = tokenID;
        this.releaseDate = releaseDate;
        this.expirationDate = expirationDate;
        this.setNumUses(numUses);
    }

    setNumUses(numUses:number):void{
        if (numUses === undefined || numUses < 0)
            throw new InvalidTokenError("Invalid numUses");

        if (numUses > MAX_USES)
            throw new MaxUsesError("Current uses exceeds more than the max")
        this.numUses = numUses;
    }

    isTokenValid():boolean{
        return (this.expirationDate.getTime() - new Date().getTime()) > 0;
    }

    convertToken(): string {
        const payload: CSRFTokenPayload = {
            tokenID: this.tokenID,
            releaseDate: this.releaseDate,
            expirationDate: this.expirationDate,
            numUses: this.numUses
        }

        return Buffer.from(JSON.stringify(payload)).toString("base64url");
    }
    
}