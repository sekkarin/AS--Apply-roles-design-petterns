import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
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
  @Roles(Role.Admin, Role.User)
  @UseGuards(AuthGuard, RolesGuard)
  @HttpCode(HttpStatus.OK)
  update(@Body() createCatDto: User) {
    return this.usersService.update(createCatDto);
  }
  @Get()
  @Roles(Role.Admin,Role.User)
  @UseGuards(AuthGuard, RolesGuard)
  @HttpCode(HttpStatus.OK)
  async getUsers() {
    return await this.usersService.getAll();
  }

  @Delete(':id')
  @Roles(Role.Admin)
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard, RolesGuard)
  async deleteUser(@Param() params: { id: string }) {
    return await this.usersService.deleteUser(params.id);
  }
  @Get(':username')
  @Roles(Role.Admin, Role.User)
  @UseGuards(AuthGuard, RolesGuard)
  async getUser(@Param() params: { username: string }) {
    // console.log("as");
    
    return await this.usersService.getUserById(params.username);
  }
}
