import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { Roles } from 'src/auth/decorator/roles.decorator';
import { Role } from 'src/auth/enums/role.enum';
import { User } from './interfaces/user.interface';
import { AuthGuard } from 'src/auth/guards/auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Patch()
  @UseGuards(AuthGuard)
  @Roles(Role.Admin)
  @Roles(Role.User)
  @HttpCode(HttpStatus.OK)
  update(@Body() createCatDto: User) {
    return this.usersService.update(createCatDto);
  }
  @Get()
  @HttpCode(HttpStatus.OK)
  async getUsers() {
    return await this.usersService.getAll();
  }

  @Roles(Role.Admin)
  @UseGuards(AuthGuard,RolesGuard)
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteUser(@Param() params: {id:string}) {
    return await this.usersService.deleteUser(params.id);
  }

}
