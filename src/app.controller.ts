import { Body, Controller, Get, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { Response } from 'express';
import * as path from 'path';
interface filePath {
  filePath: string;
}
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('getFile')
  getFile(@Res() res: Response, @Body() file: filePath) {
    res.sendFile(path.join(__dirname, '../', file.filePath));
  }
}
