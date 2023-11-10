import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthRefreshGuard } from './auth-refresh.guard';
import { UserService } from 'src/user/user.service';
import { createSpyObj } from 'jest-createspyobj';
import { verifiedUserMock } from './mocks/auth.mocks';

describe('AuthRefreshGuard', () => {
  let guard: AuthRefreshGuard;
  let jwtService: JwtService;
  let userService: UserService;

  const jwtServiceMock = createSpyObj('JwtService', ['verify']);
  const userServiceMock = createSpyObj('UserService', ['getUserByEmail']);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthRefreshGuard,
        {
          provide: JwtService,
          useValue: jwtServiceMock,
        },
        {
          provide: UserService,
          useValue: userServiceMock,
        },
      ],
    }).compile();

    guard = module.get<AuthRefreshGuard>(AuthRefreshGuard);
    jwtService = module.get<JwtService>(JwtService);
    userService = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    let context;

    beforeEach(() => {
      context = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue({
            headers: {
              authorization: 'Bearer validToken',
            },
          }),
        }),
      };
    });

    it('should throw UnauthorizedException if authorization header is missing', async () => {
      context.switchToHttp = jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          headers: {},
        }),
      });

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_throw_an_exception_if_bearer_or_token_is_missing', async () => {
      context.switchToHttp = jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          headers: {
            authorization: 'invalidFormat',
          },
        }),
      });

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_throw_an_exception_if_token_verification_fails', async () => {
      context.switchToHttp = jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          headers: {
            authorization: 'Bearer invalidToken',
          },
        }),
      });

      jwtService.verify = jest.fn().mockImplementation(() => {
        throw new Error();
      });

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_throw_an_exception_if_user_is_not_present', async () => {
      jwtService.verify = jest
        .fn()
        .mockReturnValue({ email: verifiedUserMock.email });
      userService.getUserByEmail = jest.fn().mockResolvedValue(null);

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_throw_an_exception_if_tokens_are_not_present', async () => {
      jwtService.verify = jest
        .fn()
        .mockReturnValue({ email: verifiedUserMock.email });
      userService.getUserByEmail = jest.fn().mockResolvedValue({});

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_throw_an_exception_if_refresh_token_does_not_match', async () => {
      jwtService.verify = jest
        .fn()
        .mockReturnValue({ email: verifiedUserMock.email });
      userService.getUserByEmail = jest.fn().mockResolvedValue({
        tokens: { refreshToken: 'differentToken' },
      });

      await expect(guard.canActivate(context as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should_set_user_property_in_request_and_return_true', async () => {
      const userMock = { email: verifiedUserMock.email };

      jwtService.verify = jest.fn().mockReturnValue(userMock);
      userService.getUserByEmail = jest.fn().mockResolvedValue({
        tokens: { refreshToken: 'validToken' },
      });

      const result = await guard.canActivate(context as any);

      expect(context.switchToHttp().getRequest().user).toEqual(userMock);
      expect(result).toBe(true);
    });
  });
});
