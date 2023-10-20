import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateUserResponse {
  @ApiProperty({ example: 'Signed up successfully' })
  message: string;
  @ApiProperty({
    example: {
      name: 'John Snow',
      email: 'johnsnow@gmail.com',
    },
  })
  user: {
    name: string;
    email: string;
  };
}

export class CreateUserDto {
  @ApiProperty({ type: String, name: 'name', example: 'John Snow' })
  @IsString({ message: 'Name must be a string' })
  @IsOptional()
  readonly name?: string;

  @ApiProperty({ type: String, name: 'email', example: 'johnsnow@gmail.com' })
  @IsEmail({}, { message: 'Invalid Email!' })
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsString({ message: 'Email must be a string' })
  readonly email: string;

  @ApiProperty({ type: String, name: 'password', example: 'securePhrase' })
  @IsNotEmpty({ message: 'Password must not be empty' })
  @IsString({ message: 'Password must be a string' })
  readonly password: string;

  @ApiProperty({ type: Number, name: 'age', example: 17 })
  @IsNumber({}, { message: 'Age must be a number' })
  @IsOptional()
  readonly age?: number;
}
