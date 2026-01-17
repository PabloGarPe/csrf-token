import test, { beforeEach, describe } from "node:test"
import assert, { fail } from "node:assert"
import { CsrfService } from "./csrf.service"
import { InvalidTokenError } from "./errors/invalid-token.error"
import { CSRFToken } from "./interfaces/csrf-token.interface"
import { truncate } from "node:fs"
import { MaxUsesError } from "./errors/max-uses.error"

describe("CsrfService", () => {
    let service: CsrfService

    beforeEach(() => {
        service = new CsrfService();
    })

    test("tokensMustBeDifferentEachTime", () => {
        let token1 = service.generateToken();
        let token2 = service.generateToken();
        assert.notStrictEqual(token1, token2);
    })

    test("differentTokensShouldNotValidate",() => {
        let token1 = service.generateToken();
        let token2 = service.generateToken();
        assert.equal(false,service.validateToken(token1,token2))
    })

    test("differentLengthTokensShouldNotValidate",() => {
        let token1 = service.generateToken();
        let token2 = "aaaa";
        assert.equal(false,service.validateToken(token1,token2))
    })

    test("noCookieTokenShouldNotValidate", () => {
        let token = service.generateToken();
        assert.equal(false,service.validateToken("",token))
    })

    test("noHeaderTokenShouldNotValidate", () => {
        let token = service.generateToken();
        assert.equal(false,service.validateToken(token,""))
    })

    test("sameTokenShouldValidate", () => {
        let token = service.generateToken();
        assert.equal(true,service.validateToken(token,token))
    })

    test("aValidTokenShouldDecode", () => {
        let token = service.generateToken();
        let payload = service.decodeToken(token);
        assert.notEqual(null,payload);
    })

    test("aValidTokenShouldBeValid", () => {
        let token = service.generateToken();
        let payload:CSRFToken = service.decodeToken(token);
        assert.equal(true,payload.isTokenValid())
    })

    test("aValidTokenShouldThrowErrorIfNumUsesMoreThan10", ()=>{
        let token = service.generateToken();
        let payload:CSRFToken = service.decodeToken(token);
        try {
            payload.setNumUses(11);
            fail("This should have thrown error");
        } catch (error) {
            assert.equal(true, error instanceof MaxUsesError)
        }
    })

})