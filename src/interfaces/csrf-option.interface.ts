export interface CsrfModuleOptions {
  cookieName?: string;
  headerName?: string;
  cookieOptions?: {
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
  };
  excludeRoutes?: string[];
  tokenLength?: number;
}

export interface CookieOptions {
    secure?:boolean,
    sameSite?:SameSiteOptions,
    domain?:string,
    path?:string
}

export const SameSiteOptions = {
  STRICT: 'strict',
  LAX: 'lax',
  NONE: 'none'
} as const;

export type SameSiteOptions = typeof SameSiteOptions[keyof typeof SameSiteOptions];
