import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDto } from './dto/resetPasswordDto';

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
      throw new UnauthorizedException(
        'Username does not match the provided email',
      );

    //Password comparing
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Password does not match');

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

  async resetPassword(resetPassword: ResetPasswordDto) {}
}
