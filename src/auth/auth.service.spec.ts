import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { MailerModule, MailerService } from '@nestjs-modules/mailer';
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
import { createSpyObj } from 'jest-createspyobj';
import { LoginResponse } from './dto/login.dto';
import { UserRole } from 'src/user/schemas/user.schema';
import { HttpException, HttpStatus } from '@nestjs/common';
import { SessionResponse } from './dto/session.dto';

describe('AuthService', () => {
  let service: AuthService;
  let mailerService: MailerService;
  let jwtService: JwtService;

  const userServiceMock = createSpyObj('UserService', [
    'create',
    'validateUser',
    'getUserByEmail',
  ]);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule,
        MailerModule.forRoot({
          transport: {
            host: 'testHost',
            port: 100,
            secure: false,
            auth: {
              user: 'testUser@example.com',
              pass: '123456jdh',
            },
          },
          defaults: {
            from: 'testUser@example.com',
          },
          preview: true,
        }),
      ],
      providers: [
        AuthService,
        { provide: UserService, useValue: userServiceMock },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    mailerService = module.get<MailerService>(MailerService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('registerUser', () => {
    it('should_register_a_user', async () => {
      const spyRegisterUser = userServiceMock.create.mockResolvedValue(
        mockedRegisterResponse,
      );

      const result = await service.registerUser(createUserDTOMock);

      expect(spyRegisterUser).toBeCalledTimes(1);
      expect(result).toEqual(mockedRegisterResponse);
    });
  });

  describe('login', () => {
    it('should_login_a_user_successfully', async () => {
      const spyValidateUser =
        userServiceMock.validateUser.mockResolvedValueOnce(verifiedUserMock);
      const spyGenerateTokens = jest
        .spyOn(service, 'generateTokens')
        .mockReturnValue(tokensMock);
      const expectedResult: LoginResponse = {
        message: 'Logged In successfully',
        tokens: tokensMock,
      };

      const result = await service.login(loginDtoMock);

      expect(result).toEqual(expectedResult);
      expect(spyValidateUser).toHaveBeenCalledWith(loginDtoMock);
      expect(spyGenerateTokens).toHaveBeenCalledWith({
        email: loginDtoMock.email,
        role: UserRole.USER,
      });
    });

    it('should_throw_an_exception_if_user_is_not_verified', () => {
      const spyValidateUser =
        userServiceMock.validateUser.mockResolvedValueOnce(unverifiedUserMock);

      expect(service.login(loginDtoMock)).rejects.toThrowError(
        new HttpException(`User is not verified`, HttpStatus.FORBIDDEN),
      );
      expect(spyValidateUser).toHaveBeenCalledWith(loginDtoMock);
    });
  });

  describe('sendVerificationEmail', () => {
    it('should_send_a_verification_email_to_a_new_user', async () => {
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(
          unverifiedUserMock,
        );
      const spySendEmail = jest
        .spyOn(mailerService, 'sendMail')
        .mockResolvedValueOnce({});

      const result = await service.sendVerificationEmail(
        unverifiedUserMock.email,
      );

      expect(result).toEqual({
        message: 'Verification code sent successfully!',
      });
      expect(spyGetUserByEmail).toBeCalledWith(unverifiedUserMock.email);
      expect(spySendEmail).toBeCalledTimes(1);
    });

    it('should_throw_an_exception_if_user_with_provided_email_dos_not_exist', () => {
      const invalidEmail = 'fakeEmail@gmail.com';
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(null);

      expect(service.sendVerificationEmail(invalidEmail)).rejects.toThrowError(
        new HttpException(
          `User with this email doesn't exist`,
          HttpStatus.BAD_REQUEST,
        ),
      );
      expect(spyGetUserByEmail).toBeCalledWith(invalidEmail);
    });

    it('should_throw_an_exception_if_user_with_provided_email_is_already_verified', () => {
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(verifiedUserMock);

      expect(
        service.sendVerificationEmail(verifiedUserMock.email),
      ).rejects.toThrowError(
        new HttpException(`User already verified`, HttpStatus.FORBIDDEN),
      );
      expect(spyGetUserByEmail).toBeCalledWith(verifiedUserMock.email);
    });

    it('should_throw_an_exception_if_send_email_function_throws_an_error', () => {
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(
          unverifiedUserMock,
        );
      jest
        .spyOn(mailerService, 'sendMail')
        .mockRejectedValueOnce('Failed to send email');

      expect(
        service.sendVerificationEmail(unverifiedUserMock.email),
      ).rejects.toThrowError(
        new HttpException(
          `Something went wrong!`,
          HttpStatus.INTERNAL_SERVER_ERROR,
        ),
      );
      expect(spyGetUserByEmail).toBeCalledWith(unverifiedUserMock.email);
    });
  });

  describe('verifyEmail', () => {
    it('should_verify_otp_code', async () => {
      const userMock = { ...unverifiedUserWithOtpMock };

      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(userMock);

      const result = await service.verifyEmail({
        email: userMock.email,
        code: userMock.otp,
      });

      expect(result).toEqual({ message: 'User verified successfully' });
      expect(userMock.isVerified).toBe(true);
      expect(spyGetUserByEmail).toHaveBeenCalledWith(userMock.email);
    });

    it('should_throw_an_Exception_if_user_with_provided_email_does_not_exist', () => {
      const invalidEmail = 'fakeEmail@gmail.com';
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(null);

      expect(
        service.verifyEmail({ email: invalidEmail, code: 123456 }),
      ).rejects.toThrowError(
        new HttpException(
          `User with this email doesn't exist`,
          HttpStatus.BAD_REQUEST,
        ),
      );
      expect(spyGetUserByEmail).toBeCalledWith(invalidEmail);
    });

    it('should_throw_an_exception_if_user_is_already_verified', () => {
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(verifiedUserMock);

      expect(
        service.verifyEmail({ email: verifiedUserMock.email, code: 123455 }),
      ).rejects.toThrowError(
        new HttpException(`User already verified`, HttpStatus.FORBIDDEN),
      );
      expect(spyGetUserByEmail).toBeCalledWith(verifiedUserMock.email);
    });

    it('should_throw_an_exception_if_provided_code_is_invalid', () => {
      const userMock = { ...unverifiedUserWithOtpMock };

      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(userMock);

      expect(
        service.verifyEmail({ email: userMock.email, code: 123455 }),
      ).rejects.toThrowError(
        new HttpException(`Invalid code`, HttpStatus.FORBIDDEN),
      );
      expect(spyGetUserByEmail).toBeCalledWith(userMock.email);
    });
  });

  describe('session', () => {
    it('should_return_session_of_a_user_successfully', async () => {
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(verifiedUserMock);
      const expectedResult: SessionResponse = {
        email: verifiedUserMock.email,
        name: verifiedUserMock.name,
        role: verifiedUserMock.role,
        age: verifiedUserMock.age,
      };

      const payload = { user: { email: verifiedUserMock.email } };

      const result = await service.session(payload);

      expect(result).toEqual(expectedResult);
      expect(spyGetUserByEmail).toBeCalledWith(verifiedUserMock.email);
    });
  });

  describe('logout', () => {
    it('should_logout_a_user_successfully', async () => {
      const updateOneMock = jest.fn();
      const userMock = { ...verifiedUserMock, updateOne: updateOneMock };
      const spyGetUserByEmail =
        userServiceMock.getUserByEmail.mockResolvedValueOnce(userMock);
      const payload = { user: { email: verifiedUserMock.email } };

      const result = await service.logout(payload);

      expect(result).toEqual({ message: 'User Logged out successfully!' });
      expect(spyGetUserByEmail).toBeCalledWith(verifiedUserMock.email);
      expect(userMock.updateOne).toHaveBeenCalledTimes(1);
    });
  });

  describe('generateTokens', () => {
    it('should_generate_access_and_refresh_tokens_successfully', () => {
      const spySign = jest
        .spyOn(jwtService, 'sign')
        .mockReturnValueOnce(tokensMock.accessToken)
        .mockReturnValueOnce(tokensMock.refreshToken);
      const payload = {
        email: 'johnSnow@gmail.com',
        role: UserRole.USER,
      };

      const result = service.generateTokens(payload);

      expect(result).toEqual(tokensMock);
      expect(spySign).toHaveBeenCalledTimes(2);
    });
  });
});
