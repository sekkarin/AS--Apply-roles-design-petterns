import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/interfaces/user.interface';
import * as bcrypt from 'bcrypt';
import { TokenExpiredError } from 'jsonwebtoken';
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}
  async signIn(username: string, pass: string) {
    const user = await this.usersService.findOne(username);

    const isMath = await bcrypt.compare(pass, user.password);
    if (!isMath) {
      throw new UnauthorizedException();
    }

    let payload: any = {};
    let roles: any = [];
    if (user.role.Admin) {
      roles = [user.role.Admin, user.role.User];
    } else {
      roles = [user.role.User];
    }
    payload = {
      sub: user.id,
      username: user.username,
      roles,
    };
    const refresh_token = await this.jwtService.signAsync(payload, {
      expiresIn: '1d',
    });
    user.refreshToken = refresh_token;
    await user.save();
    return {
      access_token: this.jwtService.sign(payload, { expiresIn: '30s' }),
      refresh_token: refresh_token,
    };
  }
  async signUp(Body: User) {
    const hashPassword = await bcrypt.hash(Body.password, 10);
  
    return this.usersService.createUser({
      ...Body,
      password: hashPassword,
      role: { ...Body.role },
      isAlive: true,
    });
  }
  async refresh(refreshToken: string) {
    try {
      const foundUser = await this.usersService.findOneToken(refreshToken);
      if (!foundUser) {
        throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
      }

      try {
        const verifyToken = this.jwtService.verify(refreshToken);
        if (verifyToken.username != foundUser.username) {
          throw new ForbiddenException();
        }
        let roles: any = [];
        if (foundUser.role.Admin) {
          roles = [foundUser.role.Admin, foundUser.role.User];
        } else {
          roles = [foundUser.role.User];
        }
        const payload = {
          sub: foundUser.id,
          username: foundUser.username,
          roles: roles,
        };
        return await this.jwtService.signAsync(payload, { expiresIn: '20s' });
      } catch (error) {
        throw new ForbiddenException();
      }
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
  async logOut(username: string): Promise<User | undefined> {
    console.log("work?");
    
    try {
      const fondUser = await this.usersService.findOne(username);
      if (!fondUser) {
        throw new HttpException('FORBIDDEN', HttpStatus.FORBIDDEN);
      }
      fondUser.refreshToken = '';

      return await fondUser.save();
    } catch (error) {
      console.log(error);
      
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
