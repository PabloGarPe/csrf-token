import { Test, TestingModule } from '@nestjs/testing';
import { CSRFModule } from './csrf.module';
import { CsrfService } from './csrf.service';
import { CsrfGuard } from './csrf.guard';
import { describe, beforeEach, it } from 'node:test';
import assert, { fail } from "node:assert"

describe('CsrfModule', () => {
  let module: TestingModule;

  beforeEach(async () => {
    module = await Test.createTestingModule({
      imports: [
        CSRFModule.forRoot({
          cookieName: 'TEST-TOKEN',
          excludeRoutes: ['/health'],
        }),
      ],
    }).compile();
  });

  it('should provide CsrfService', () => {
    const service = module.get<CsrfService>(CsrfService);
    assert.notEqual(undefined,service);
  });

  it('should provide CsrfGuard', () => {
    const guard = module.get<CsrfGuard>(CsrfGuard);
    assert.notEqual(undefined,guard);
  });
});