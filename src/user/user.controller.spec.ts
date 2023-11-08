import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { createSpyObj } from 'jest-createspyobj';
import { JwtModule } from '@nestjs/jwt';

describe('UserController', () => {
  let controller: UserController;

  const userServiceMock = createSpyObj('UserService', [
    'create',
    'validateUser',
    'getUserByEmail',
    'deleteUser',
  ]);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      imports: [JwtModule],
      providers: [{ provide: UserService, useValue: userServiceMock }],
    }).compile();

    controller = module.get<UserController>(UserController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('deleteUser', () => {
    it('should_delete_a_provided_user_successfully', async () => {
      const mockedUserId = 's0meus3rid';
      const expectedResult = { message: 'User deleted successfully!' };
      const spyDeleteUser =
        userServiceMock.deleteUser.mockResolvedValueOnce(expectedResult);

      const result = await controller.deleteUser({ userId: mockedUserId });

      expect(result).toEqual(expectedResult);
      expect(spyDeleteUser).toHaveBeenLastCalledWith(mockedUserId);
    });
  });
});
