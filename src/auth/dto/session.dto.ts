import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from 'src/user/schemas/user.schema';

export class SessionResponse {
  @ApiProperty({ example: 'John Snow' })
  readonly name: string;

  @ApiProperty({ example: 'johnsnow@gmail.com' })
  readonly email: string;

  @ApiProperty({ example: 17 })
  readonly age: number;

  @ApiProperty({ example: UserRole.ADMIN })
  readonly role: UserRole;
}
