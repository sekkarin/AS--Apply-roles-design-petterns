import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from 'src/users/interfaces/user.interface';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService, // private jwtService: JwtService,
  ) {}
  // @HttpCode(HttpStatus.OK)
  @Post('login')
  async signIn(@Body() signInDto: Record<string, any>, @Res() res: Response) {
    console.log("signInDto",signInDto);
    
    if (!signInDto.password && !signInDto.username ) {
      throw new UnauthorizedException();
    }
    const user = this.authService.signIn(
      signInDto.username,
      signInDto.password,
    );
    res.cookie('refresh_token', (await user).access_token, {
      httpOnly: true,
      sameSite: 'none',
      secure: true, // prod needed!
      maxAge: 24 * 60 * 60 * 1000, // 1 day in ms unit
    });
    res.status(200).json({ access_token: (await user).access_token });
  }


  @HttpCode(HttpStatus.OK)
  @Post('register')
  signUp(@Body() signUpDto: User) {
    console.log("register");
    
    if (!signUpDto.password && !signUpDto.username ) {
      throw new UnauthorizedException();
    }
    return this.authService.signUp(signUpDto);
  }
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    const cookies = req.cookies;
    if (!cookies.refresh_token) {
      throw new UnauthorizedException();
    }

    const access_token = await this.authService.refresh(cookies.refresh_token);
    res.status(200).json({access_token});
  }
}
