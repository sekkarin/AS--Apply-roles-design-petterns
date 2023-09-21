import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { corsOptions } from './utils/corsOptions';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as path from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.use(cookieParser());
  app.useStaticAssets(path.join(__dirname, '../'));
  app.enableCors({ ...corsOptions });
  // app.enableCors(options);
  await app.listen(3000);
}
bootstrap();
