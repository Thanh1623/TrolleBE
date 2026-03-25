import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto/login.dto';
import { RegisterDto } from './dto/register.dto/register.dto';
import { GoogleAuthGuard } from 'src/modules/auth/google-auth.guard';
import type { Request, Response } from 'express';
import { ContinueDto } from './dto/continue.dto/continue.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @Post('login')
  // login(@Body() body: LoginDto) {
  //   return this.authService.login(body);
  // }
  // @Post('register')
  // register(@Body() dto: RegisterDto) {
  //   return this.authService.register(dto);
  // }

  // @Post('continue')
  // continue(@Body('email') email: string) {
  //   return this.authService.continueAuth(email);
  // }

  @Post('continue')
  continue(@Body() dto: ContinueDto) {
    return this.authService.continueAuth(dto.email);
  }

  @Post('login')
  async login(@Body() dto: LoginDto, @Res() res) {
    const tokens: any = await this.authService.login(dto);
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return res.json(tokens);
  }

  @Post('register')
  async register(@Body() dto: RegisterDto, @Res() res) {
    const tokens: any = await this.authService.register(dto);
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return res.json(tokens);
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  googleLogin() {}

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleRedirect(@Req() req: Request, @Res() res: Response) {
    const user = req.user;

    const tokens = await this.authService.handleGoogleLogin(user);

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });

    return res.redirect('http://localhost:5173');
  }
  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }
}
