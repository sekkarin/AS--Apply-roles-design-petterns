import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from 'src/users/interfaces/user.interface';
import { Request, Response } from 'express';
import { Roles } from './decorator/roles.decorator';
import { Role } from './enums/role.enum';
import { AuthGuard } from './guards/auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { FileInterceptor } from '@nestjs/platform-express';
// import { MyLoggerService } from 'src/my-logger/my-logger.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService, // private myLogger: MyLoggerService// private jwtService: JwtService,
  ) {}
  @Post('login')
  async signIn(@Body() signInDto: Record<string, any>, @Res() res: Response) {
    if (!signInDto.password && !signInDto.username) {
      throw new UnauthorizedException();
    }
    const user = await this.authService.signIn(
      signInDto.username,
      signInDto.password,
    );
    res.cookie('refreshToken', user.refresh_token, {
      httpOnly: true,
      sameSite: 'none',
      secure: true, // prod needed!
      maxAge: 24 * 60 * 60 * 1000, // 1 day in ms unit
    });
    return res.status(200).json({ access_token: user.access_token });
  }

  @HttpCode(HttpStatus.OK)
  @Post('register')
  signUp(@Body() signUpDto: User) {
    if (!signUpDto.password && !signUpDto.username) {
      throw new UnauthorizedException();
    }
    return this.authService.signUp(signUpDto);
  }

  // @HttpCode(HttpStatus.OK)
  @Get('refresh')
  async refresh(@Req() request: Request, @Res() res: Response) {
    const cookies = request.cookies;
    if (!cookies.refreshToken) {
      throw new UnauthorizedException();
    }
    const access_token = await this.authService.refresh(cookies.refreshToken);
    res.status(200).json({ access_token });
  }

  @Post('logout')
  @Roles(Role.Admin, Role.User)
  @UseGuards(AuthGuard, RolesGuard)
  async logOut(@Req() req: Request, @Res() res: Response) {
    const { username } = req.user;
    const logout = await this.authService.logOut(username);
    if (!logout) {
      res.status(403);
    }
    res.clearCookie('refreshToken');
    res.status(200).json({ message: "logout's" });
  }
  
  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  uploadFile(@UploadedFile() file: Express.Multer.File) {
    // console.log(req);

    console.log(file);
    if (file) {
      return { filename: file.path };
    } else {
      return {};
    }
  }
}
