import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmation';
import { DeleteAccountDto } from './dto/deleteAccountDto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signup(signupDto: SignupDto) {
    const { email, password, username } = signupDto;

    //User Verfication
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (user) throw new ConflictException('User already exists');

    //Password Hashing
    const hash = await bcrypt.hash(password, 10);

    //Save User
    await this.prismaService.user.create({
      data: { email, username, password: hash },
    });

    //Email Confirmation
    await this.mailerService.sendSignupConfirmation(email);

    //Returning Success Response
    return { data: 'User created successfully' };
  }

  async signin(signinDto: SigninDto) {
    const { email, password, username } = signinDto;

    //Verify if User exists
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    //Verify if User is linked to a email
    if (user.username !== username)
      throw new UnauthorizedException('Username error');

    //Password comparing
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Password error');

    //Token JWT returning
    const payload = {
      sub: user.userId,
      email: user.email,
    };
    const token = this.jwtService.sign(payload, {
      expiresIn: '1h',
      secret: this.configService.get('SECRET_KEY'),
    });
    return {
      token,
      user: {
        username: user.username,
        email: user.email,
      },
    };
  }

  async resetPasswordDemand(resetPasswordDemandDto: ResetPasswordDemandDto) {
    const { email } = resetPasswordDemandDto;
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const code = speakeasy.totp({
      secret: this.configService.get('OTP_CODE'),
      digits: 5,
      step: 60 * 5,
      encoding: 'base32',
    });
    const url = 'http://localhost:3000/auth/reset-password-confirmation';
    await this.mailerService.sendResetPassword(email, url, code);
    return { data: 'Reset password email has been sent' };
  }

  async resetPasswordConfirmation(resetPasswordConfirmationDto: ResetPasswordConfirmationDto) {
    const { email, code, password } = resetPasswordConfirmationDto;
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const match = speakeasy.totp.verify({
      secret: this.configService.get('OTP_CODE'),
      token: code,
      digits: 5,
      step: 60 * 5,
      encoding: 'base32',
    });
    if (!match) throw new UnauthorizedException('Invalid or expired token');
    const hash = await bcrypt.hash(password, 10);
    await this.prismaService.user.update({
      where: { email },
      data: { password: hash },
    });
    return { data: 'Password changed successfully' };
  }

  async deleteAccount(userId: any, deleteAccountDto: DeleteAccountDto) {
    const { password } = deleteAccountDto;

    const user = await this.prismaService.user.findUnique({
      where: { userId },
    });
    if (!user) throw new NotFoundException('User not found');

    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Password error');

    await this.prismaService.user.delete({ where: { userId } });
    return { data: 'User deleted' };
  }
}
