import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { JWTTokens } from 'src/user/schemas/user.schema';

export class LoginResponse {
  @ApiProperty({ example: 'Logged In successfully' })
  message: string;
  @ApiProperty({
    example: {
      accessToken: 'JWTAccessToken',
      refreshToken: 'JWTRefreshToken',
    },
  })
  tokens: JWTTokens;
}

export class LoginDTO {
  @ApiProperty({ type: String, name: 'email', example: 'johnSnow@gmail.com' })
  @IsEmail({}, { message: 'Invalid Email!' })
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsString({ message: 'Email must be a string' })
  readonly email: string;

  @ApiProperty({ type: String, name: 'password', example: 'securePhrase' })
  @IsNotEmpty({ message: 'Password must not be empty' })
  @IsString({ message: 'Password must be a string' })
  readonly password: string;
}
