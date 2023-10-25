import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { createSpyObj } from 'jest-createspyobj';
import { JwtModule } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import {
  createUserDTOMock,
  loginDtoMock,
  mockedRegisterResponse,
  tokensMock,
  unverifiedUserMock,
  unverifiedUserWithOtpMock,
  verifiedUserMock,
} from './mocks/auth.mocks';
import { LoginResponse } from './dto/login.dto';
import { UserRole } from 'src/user/schemas/user.schema';
import { Request } from 'express';
import { SessionResponse } from './dto/session.dto';

describe('AuthController', () => {
  let controller: AuthController;
  const authServiceMock = createSpyObj('AuthService', [
    'registerUser',
    'login',
    'sendVerificationEmail',
    'verifyEmail',
    'session',
    'logout',
    'generateTokens',
  ]);

  const userServiceMock = createSpyObj('UserService', [
    'create',
    'validateUser',
    'getUserByEmail',
  ]);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      imports: [JwtModule],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: UserService, useValue: userServiceMock },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should_register_a_user_and_return_its_attributes', async () => {
      const spyRegister = authServiceMock.registerUser.mockResolvedValueOnce(
        mockedRegisterResponse,
      );

      const result = await controller.register(createUserDTOMock);

      expect(result).toEqual(mockedRegisterResponse);
      expect(spyRegister).toHaveBeenCalledWith(createUserDTOMock);
    });
  });

  describe('login', () => {
    it('should_login_a_user_and_return_tokens', async () => {
      const expectedResult: LoginResponse = {
        message: 'Logged In successfully',
        tokens: tokensMock,
      };
      const spyLogin =
        authServiceMock.login.mockResolvedValueOnce(expectedResult);

      const result = await controller.login(loginDtoMock);

      expect(result).toEqual(expectedResult);
      expect(spyLogin).toHaveBeenCalledWith(loginDtoMock);
    });
  });

  describe('sendEmail', () => {
    it('should_email_verification_code_to_user', async () => {
      const expectedResult = {
        message: 'Verification code sent successfully!',
      };
      const email = unverifiedUserMock.email;
      const spySendEmail =
        authServiceMock.sendVerificationEmail.mockResolvedValueOnce(
          expectedResult,
        );

      const result = await controller.sendEmail({ email });

      expect(result).toEqual(expectedResult);
      expect(spySendEmail).toHaveBeenCalledWith(email);
    });
  });

  describe('verifyEmail', () => {
    it('should_verify_a_user_through_otp_sent_to_his_email', async () => {
      const payload = {
        code: unverifiedUserWithOtpMock.otp,
        email: unverifiedUserWithOtpMock.email,
      };
      const expectedResult = { message: 'User verified successfully' };
      const spyVerifyEmail =
        authServiceMock.verifyEmail.mockResolvedValueOnce(expectedResult);

      const result = await controller.verifyEmail(payload);

      expect(result).toEqual(expectedResult);
      expect(spyVerifyEmail).toHaveBeenCalledWith(payload);
    });
  });

  describe('getSession', () => {
    it('should_get_session_of_a_logged_in_user', async () => {
      const expectedResult: SessionResponse = {
        email: verifiedUserMock.email,
        name: verifiedUserMock.name,
        role: verifiedUserMock.role,
        age: verifiedUserMock.age,
      };
      const spySession =
        authServiceMock.session.mockResolvedValueOnce(expectedResult);
      const req: Partial<Request> = {
        user: {
          email: 'johnSnow@gmail.com',
          role: UserRole.USER,
        },
      } as Partial<Request>;

      const result = await controller.getSession(req as Request);

      expect(result).toEqual(expectedResult);
      expect(spySession).toHaveBeenCalledWith(req);
    });
  });

  describe('logout', () => {
    it('should_logout_a_user', async () => {
      const req: Partial<Request> = {
        user: {
          email: 'johnSnow@gmail.com',
          role: UserRole.USER,
        },
      } as Partial<Request>;
      const expectedResult = { message: 'User Logged out successfully!' };
      const spyLogout =
        authServiceMock.logout.mockResolvedValueOnce(expectedResult);

      const result = await controller.logout(req as Request);

      expect(result).toEqual(expectedResult);
      expect(spyLogout).toHaveBeenCalledWith(req);
    });
  });
});
