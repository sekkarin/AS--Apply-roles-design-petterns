import {
  HttpException,
  HttpStatus,
  Injectable,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/interfaces/user.interface';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';
import { SignOptions, TokenExpiredError } from 'jsonwebtoken';
import { Role } from './enums/role.enum';
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}
  async signIn(username: string, pass: string) {
    const user = await this.usersService.findOne(username);
    // console.log(user);
    const isMath = await bcrypt.compare(pass, user.password);
    if (!isMath) {
      throw new UnauthorizedException();
    }
    const payload = { sub: user.id, username: user.username, roles: [{...user.role}] };
    const refresh_token = await this.jwtService.signAsync(payload, {
      expiresIn: '1 Days',
    });
    user.refreshToken = refresh_token;
    await user.save();
    return {
      access_token: await this.jwtService.signAsync(payload),
      refresh_token: refresh_token,
    };
  }
  async signUp(Body: User) {
    const hashPasword = await bcrypt.hash(Body.password, 10);

    return this.usersService.createUser({
      ...Body,
      password: hashPasword,
      role: [{ ...Body.role }],
      isAlive: true,
    });
  }
  async refresh(refreshToken: string) {
    try {
      const verifyToken = this.jwtService.verify(refreshToken);
      const foudUser = await this.usersService.findOne(verifyToken.username);
      if (!foudUser) {
        throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
      }
      if (foudUser.username !== verifyToken.username) {
        throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
      }
      const payload = { sub: foudUser.id, username: foudUser.username };
      return await this.jwtService.signAsync(payload);
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
      }
      throw new HttpException(
        'INTERNAL_SERVER_ERROR',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
