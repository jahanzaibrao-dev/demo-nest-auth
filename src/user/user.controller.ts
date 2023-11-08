import { Controller, Delete, Param, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiTags } from '@nestjs/swagger';
import { UserService } from './user.service';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from './schemas/user.schema';
import { AuthGuard } from 'src/auth/auth.guard';
import { RolesGuard } from 'src/auth/roles.guard';
import { UserIdDTO } from './dto/delete-user.dto';

@Controller('user')
@ApiTags('User')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Delete('/:userId')
  @ApiBearerAuth()
  @Roles(UserRole.ADMIN)
  @UseGuards(AuthGuard, RolesGuard)
  @ApiParam({
    name: 'userId',
    type: String,
    required: true,
    example: 'm0ng0obj3ctid',
  })
  deleteUser(@Param() params: UserIdDTO) {
    return this.userService.deleteUser(params.userId);
  }
}
