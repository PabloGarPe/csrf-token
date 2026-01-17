import { CsrfModuleOptions } from "./interfaces/csrf-option.interface";

export const CSRF_DEFAULT_TOKEN_LENGTH = 32;
export const CSRF_DEFAULT_COOKIE_NAME = "XSRF-TOKEN";
export const CSRF_DEFAULT_HEADER_NAME = "x-csrf-token";
export const MAX_USES = 10;

export const CSRF_DEFAULT_OPTIONS: CsrfModuleOptions = {
    cookieName: CSRF_DEFAULT_COOKIE_NAME,
    headerName: CSRF_DEFAULT_HEADER_NAME,
    tokenLength: CSRF_DEFAULT_TOKEN_LENGTH
};