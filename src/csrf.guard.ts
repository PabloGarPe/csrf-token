import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import { CsrfService } from "./csrf.service";
import { Reflector } from "@nestjs/core";
import { CSRF_DEFAULT_COOKIE_NAME, CSRF_DEFAULT_HEADER_NAME, CSRF_DEFAULT_PATH, CSRF_DEFAULT_SAME_SITE, CSRF_DEFAULT_SECURE, CSRF_OPTIONS } from "./constants";
import { CsrfModuleOptions } from "./interfaces/csrf-option.interface";

@Injectable()
export class CsrfGuard implements CanActivate {

    constructor(private readonly csrfService:CsrfService,
        private readonly reflector:Reflector,
        @Inject(CSRF_OPTIONS) private readonly options:CsrfModuleOptions
    ) {}


    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();

        if(this.isRouteExcluded(request.path))
            return true;

        const cookieName = this.options.cookieName || CSRF_DEFAULT_COOKIE_NAME;
        const headerName = this.options.headerName || CSRF_DEFAULT_HEADER_NAME;

        const cookieToken = request.cookies?.[cookieName]
        const headerToken = request.headers[headerName.toLowerCase()]

        if(!cookieToken && !headerToken){
            let token = this.csrfService.generateToken();
            token = this.csrfService.useToken(token);
            this.sendCookie(token,response,cookieName);
            return true;
        }

        if(!this.csrfService.validateToken(cookieToken,headerToken))
            throw new ForbiddenException("Token missmatch");

        let token = this.csrfService.decodeToken(cookieToken);

        if(!token.isTokenValid()){
            let newToken = this.csrfService.generateToken();
            newToken = this.csrfService.useToken(newToken);
            this.sendCookie(newToken,response,cookieName);
            return true;
        }

        this.sendCookie(this.csrfService.useToken(cookieToken),response,cookieName);


    }

    private isRouteExcluded(path:string): boolean {
        if (!this.options.excludeRoutes)
            return false

        return this.options.excludeRoutes.some(route => {
            if (route.endsWith('*'))
                return path.startsWith(route.slice(0,-1));
            return path === route;
        })
    }

    private sendCookie(token:string,response:any,cookieName:string){
        response.cookie(cookieName,token,{
                httpOnly:false,
                secure: this.options.cookieOptions?.secure ?? CSRF_DEFAULT_SECURE,
                sameSite: this.options.cookieOptions?.sameSite ?? CSRF_DEFAULT_SAME_SITE,
                path: this.options.cookieOptions?.path ?? CSRF_DEFAULT_PATH,
                domain: this.options.cookieOptions?.domain
            })
    }

}