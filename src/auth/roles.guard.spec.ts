import { Test, TestingModule } from '@nestjs/testing';
import { RolesGuard } from './roles.guard';
import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { UserRole } from 'src/user/schemas/user.schema';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RolesGuard, Reflector],
    }).compile();

    guard = module.get<RolesGuard>(RolesGuard);
    reflector = module.get<Reflector>(Reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should_return_true_if_no_roles_are_required', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
      const context = createContext();

      const result = guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should_return_true_if_user_role_matches_required_role', () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue([UserRole.ADMIN]);
      const context = createContext({ user: { role: UserRole.ADMIN } });

      const result = guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should_return_false_if_user_role_does_not_match_any_required_role', () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue([UserRole.ADMIN]);
      const context = createContext({ user: { role: UserRole.USER } });

      const result = guard.canActivate(context);

      expect(result).toBe(false);
    });
  });

  function createContext(request?: any, handler?: any): ExecutionContext {
    return {
      switchToHttp: () => ({ getRequest: () => request || {} }),
      getHandler: handler || jest.fn(),
      getClass: jest.fn() as any,
    } as ExecutionContext;
  }
});
