import {
  CreateUserDto,
  CreateUserResponse,
} from 'src/user/dto/create-user.dto';
import { LoginDTO } from '../dto/login.dto';
import { UserRole } from 'src/user/schemas/user.schema';

export const createUserDTOMock: CreateUserDto = {
  name: 'John Snow',
  email: 'johnsnow@gmail.com',
  password: 'testPassword',
  age: 17,
};

export const loginDtoMock: LoginDTO = {
  email: 'johnsnow@gmail.com',
  password: 'testPassword',
};

export const verifiedUserMock = {
  ...createUserDTOMock,
  isVerified: true,
  role: UserRole.USER,
  save: async () => {},
};

export const unverifiedUserMock = {
  ...createUserDTOMock,
  isVerified: false,
  role: UserRole.USER,
  save: async () => {},
};

export const unverifiedUserWithOtpMock = {
  ...unverifiedUserMock,
  otp: 536478,
};

export const tokensMock = {
  accessToken: 'T3stAcc3ssT0k3n',
  refreshToken: 'T3stR3fr3shT0k3n',
};

export const mockedRegisterResponse: CreateUserResponse = {
  message: 'Signed up successfully',
  user: {
    email: 'johnSnow@gmail.com',
    name: 'John Snow',
  },
};
