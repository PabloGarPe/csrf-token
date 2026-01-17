export class MaxUsesError extends Error {
    constructor(message:string){
        super(message);
        this.name = "MaxUsesError";
        Object.setPrototypeOf(this,MaxUsesError.prototype);
    }
}