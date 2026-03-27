import { BadRequestException, Injectable } from '@nestjs/common';
import { LoginDto } from './dto/login.dto/login.dto';
import { RegisterDto } from './dto/register.dto/register.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
// import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  generateTokens(user) {
    return {
      accessToken: this.jwtService.sign({ sub: user.id }),
      refreshToken: this.jwtService.sign({ sub: user.id }, { expiresIn: '7d' }),
    };
  }

  async login(data: LoginDto) {
    const { email } = data;
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('User not found or invalid credentials');
    }
    return {
      message: 'Login success',
      email,
    };
  }

  async register(dto: RegisterDto) {
    const { email } = dto;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const user = await this.prisma.user.create({
      data: { email },
    });

    return {
      message: 'Register success',
      user,
    };
  }

  // async login(dto: LoginDto) {
  //   const user = await this.prisma.user.findUnique({
  //     where: { email: dto.email },
  //   });

  //   if (!user) throw new Error('User not found');

  //   const match = await bcrypt.compare(dto.password, user.password);

  //   if (!match) throw new Error('Wrong password');

  //   return this.generateTokens(user);
  // }

  // async register(dto: RegisterDto) {
  //   const hash = await bcrypt.hash(dto.password, 10);

  //   const user = await this.prisma.user.create({
  //     data: {
  //       email: dto.email,
  //       password: hash,
  //     },
  //   });
  //   // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  //   return this.generateTokens(user);
  // }

  async continueAuth(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    return {
      type: user ? 'login' : 'register',
    };
  }

  async handleGoogleLogin(googleUser: any) {
    const { email, name } = googleUser;

    // 1. check user tồn tại chưa
    let user = await this.prisma.user.findUnique({
      where: { email },
    });

    // 2. nếu chưa có → tạo mới
    if (!user) {
      user = await this.prisma.user.create({
        data: {
          email,
          name,
          password: '', // google không cần password
        },
      });
    }

    // 3. tạo token
    const accessToken = this.jwtService.sign({
      sub: user.id,
    });

    const refreshToken = this.jwtService.sign(
      { sub: user.id },
      { expiresIn: '7d' },
    );

    return { accessToken, refreshToken };
  }

  async sendOtp(email: string) {
    // 1. tạo mã OTP
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // 2. lưu DB
    await this.prisma.otp.create({
      data: {
        email,
        code,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 phút
      },
    });

    // 3. gửi email (tạm log)
    console.log('OTP:', code);
    return { message: 'OTP sent to email' };
  }

  async verifyOtp(email: string, code: string) {
    const otp = await this.prisma.otp.findFirst({
      where: { email, code },
    });

    if (!otp) throw new Error('Invalid OTP');

    if (otp.expiresAt < new Date()) {
      throw new Error('OTP expired');
    }

    // Xóa OTP sau khi dùng
    await this.prisma.otp.delete({
      where: { id: otp.id },
    });

    // 1. check user
    let user = await this.prisma.user.findUnique({
      where: { email },
    });

    // 2. chưa có → tạo mới
    if (!user) {
      user = await this.prisma.user.create({
        data: {
          email,
          provider: 'otp',
        },
      });
    }

    // 3. trả token
    return this.generateTokens(user);
  }
}
