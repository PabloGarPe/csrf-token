import { DynamicModule, Global,Module } from "@nestjs/common";
import { CsrfModuleOptions } from "./interfaces/csrf-option.interface";
import { CSRF_OPTIONS } from "./constants";
import { CsrfService } from "./csrf.service";
import { CsrfGuard } from "./csrf.guard";
import { APP_GUARD } from "@nestjs/core";

@Global()
@Module({})
export class CSRFModule{
    static forRoot(options: CsrfModuleOptions = {}): DynamicModule {
    return {
      module: CSRFModule,
      providers: [
        {
          provide: CSRF_OPTIONS,
          useValue: options,
        },
        {
          provide: CsrfService,
          useFactory: (opts: CsrfModuleOptions) => {
            return new CsrfService(opts.tokenLength);
          },
          inject: [CSRF_OPTIONS],
        },
        CsrfGuard,
        {
          provide: APP_GUARD,
          useClass: CsrfGuard,
        },
      ],
      exports: [CsrfService, CSRF_OPTIONS],
    };
  }
  
  static forRootAsync(options: {
    useFactory: (...args: any[]) => Promise<CsrfModuleOptions> | CsrfModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: CSRFModule,
      providers: [
        {
          provide: CSRF_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        {
          provide: CsrfService,
          useFactory: (opts: CsrfModuleOptions) => {
            return new CsrfService(opts.tokenLength);
          },
          inject: [CSRF_OPTIONS],
        },
        CsrfGuard,
        {
          provide: APP_GUARD,
          useClass: CsrfGuard,
        },
      ],
      exports: [CsrfService, CSRF_OPTIONS],
    };
  }
}