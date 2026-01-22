import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CsrfToken = createParamDecorator(
  (cookieName: string = 'XSRF-TOKEN', ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const response = ctx.switchToHttp().getResponse();
    
    let token = request.cookies?.[cookieName];
    
    if (!token) {
      const crypto = require('crypto');
      token = crypto.randomBytes(32).toString('base64url');
      response.cookie(cookieName, token, {
        httpOnly: false,
        secure: true,
        sameSite: 'strict',
      });
    }
    
    return token;
  },
);

export const SkipCsrf = () => {
  return (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) => {
    // TODO: Expand later
  };
};