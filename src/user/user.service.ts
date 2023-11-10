import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto, CreateUserResponse } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { LoginDTO } from 'src/auth/dto/login.dto';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private user: Model<User>) {}
  async create(createUserDto: CreateUserDto): Promise<CreateUserResponse> {
    const userExist = await this.user.findOne({ email: createUserDto.email });
    if (userExist) {
      throw new HttpException('User already exists', HttpStatus.FORBIDDEN);
    }
    const hashedPassword = await bcrypt.hash(createUserDto.password, 5);
    const newUser = await this.user.create({
      ...createUserDto,
      password: hashedPassword,
    });

    return {
      message: 'Signed up successfully',
      user: {
        name: newUser.name,
        email: newUser.email,
      },
    };
  }

  async validateUser(loginDto: LoginDTO) {
    const user = await this.user.findOne({ email: loginDto.email });
    if (!user) {
      throw new HttpException(
        `The provided username or password is incorrect`,
        HttpStatus.BAD_REQUEST,
      );
    }

    const isValidPass = await bcrypt.compare(loginDto.password, user.password);

    if (!isValidPass) {
      throw new HttpException(
        `The provided username or password is incorrect`,
        HttpStatus.BAD_REQUEST,
      );
    }

    return user;
  }

  async deleteUser(id: string) {
    const userExist = await this.user.findOne({ _id: id });
    if (!userExist) {
      throw new HttpException(
        `User with this id doesn't exist`,
        HttpStatus.BAD_REQUEST,
      );
    }

    await this.user.deleteOne({ _id: id });

    return {
      message: 'User deleted successfully!',
    };
  }

  async getUserByEmail(email: string) {
    return this.user.findOne({ email });
  }
}
