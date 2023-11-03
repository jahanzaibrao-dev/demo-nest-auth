import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { JWTTokens } from 'src/user/schemas/user.schema';

export class TokensResponse {
  @ApiProperty({ example: 'Success Message' })
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
  @IsDefined({ message: 'Email must be defined' })
  readonly email: string;

  @ApiProperty({ type: String, name: 'password', example: 'securePhrase' })
  @IsNotEmpty({ message: 'Password must not be empty' })
  @IsString({ message: 'Password must be a string' })
  @IsDefined({ message: 'Password must be defined' })
  readonly password: string;
}
