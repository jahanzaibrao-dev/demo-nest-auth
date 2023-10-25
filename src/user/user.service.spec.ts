import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { getModelToken } from '@nestjs/mongoose';
import {
  createUserDTOMock,
  loginDtoMock,
  mockedRegisterResponse,
  unverifiedUserMock,
  verifiedUserMock,
} from 'src/auth/mocks/auth.mocks';
import * as bcrypt from 'bcryptjs';
import { createSpyObj } from 'jest-createspyobj';
import { HttpException, HttpStatus } from '@nestjs/common';

describe('UserService', () => {
  let service: UserService;
  let userModel: Model<User>;
  const userModelMock = createSpyObj('User', ['findOne', 'create']);
  const createSpy = jest.fn();

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getModelToken(User.name),
          useValue: userModelMock,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    userModel = module.get<Model<User>>(getModelToken(User.name));
    userModelMock.create = jest.fn().mockImplementation((createUserDto) => ({
      ...createUserDto,
      _id: 'uniqueId',
      save: createSpy,
    }));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should_create_a_user_successfully', async () => {
      const findOneSpy = userModelMock.findOne.mockResolvedValueOnce(null);
      const createSpy =
        userModelMock.create.mockResolvedValueOnce(unverifiedUserMock);

      const hashedPassword = 'h@sh3dP@ssw0rd';
      const spyBcryptHash = (bcrypt.hash = jest
        .fn()
        .mockResolvedValueOnce(hashedPassword));

      const result = await service.create(createUserDTOMock);

      expect(result).toEqual(mockedRegisterResponse);
      expect(findOneSpy).toHaveBeenCalledTimes(1);
      expect(spyBcryptHash).toHaveBeenCalledTimes(1);
      expect(createSpy).toHaveBeenCalledTimes(1);
    });

    it('should_throw_an_exception_if_user_already_exists', () => {
      const findOneSpy =
        userModelMock.findOne.mockResolvedValueOnce(verifiedUserMock);

      expect(service.create(createUserDTOMock)).rejects.toThrowError(
        new HttpException('User already exists', HttpStatus.BAD_REQUEST),
      );
      expect(findOneSpy).toHaveBeenCalledWith({
        email: createUserDTOMock.email,
      });
    });
  });

  describe('validateUser', () => {
    it('should_validate_and_return_a_user_successfully', async () => {
      const findOneSpy =
        userModelMock.findOne.mockResolvedValueOnce(verifiedUserMock);
      const spyBcryptCompare = (bcrypt.compare = jest
        .fn()
        .mockResolvedValueOnce(true));

      const result = await service.validateUser(loginDtoMock);

      expect(result).toEqual(verifiedUserMock);
      expect(findOneSpy).toHaveBeenCalledWith({
        email: loginDtoMock.email,
      });
      expect(spyBcryptCompare).toHaveBeenCalledTimes(1);
    });

    it('should_throw_an_exception_if_email_is_incorrect', () => {
      const findOneSpy = userModelMock.findOne.mockResolvedValueOnce(null);

      expect(service.validateUser(loginDtoMock)).rejects.toThrowError(
        new HttpException(
          `The provided username or password is incorrect`,
          HttpStatus.BAD_REQUEST,
        ),
      );
      expect(findOneSpy).toHaveBeenCalledWith({
        email: loginDtoMock.email,
      });
    });

    it('should_throw_an_exception_if_password_is_incorrect', () => {
      const payload = { ...loginDtoMock };
      payload.password = 'wr0ngP@ssw0rd';
      const findOneSpy =
        userModelMock.findOne.mockResolvedValueOnce(verifiedUserMock);
      const spyBcryptCompare = (bcrypt.compare = jest
        .fn()
        .mockResolvedValueOnce(false));

      expect(service.validateUser(payload)).rejects.toThrowError(
        new HttpException(
          `The provided username or password is incorrect`,
          HttpStatus.BAD_REQUEST,
        ),
      );
      expect(findOneSpy).toHaveBeenCalledWith({
        email: loginDtoMock.email,
      });
    });
  });

  describe('getUserByEmail', () => {
    it('should_get_a_user_from_db_through_his_email', async () => {
      const findOneSpy =
        userModelMock.findOne.mockResolvedValueOnce(verifiedUserMock);

      const result = await service.getUserByEmail(verifiedUserMock.email);

      expect(result).toEqual(verifiedUserMock);
      expect(findOneSpy).toHaveBeenCalledWith({
        email: verifiedUserMock.email,
      });
    });
  });
});
