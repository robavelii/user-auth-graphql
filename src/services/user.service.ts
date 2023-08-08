import { CreateUserInput, LoginInput, UserModel } from '../models/user.schema';
import Context from '../types/context';
import bcrypt from 'bcrypt';
import { GraphQLError } from 'graphql';
import * as OTPAuth from 'otpauth';
import { encode } from 'hi-base32';
import crypto from 'crypto';
import { signJwt } from '../utils/jwt';

class UserService {
  async createUser(input: CreateUserInput) {
    return UserModel.create(input);
  }

  async login(input: LoginInput, context: Context) {
    const e = 'Invalid email or password';

    const user = await UserModel.find().findByEmail(input.email).lean();

    if (!user) {
      throw new GraphQLError(e);
    }

    const passwordIsValid = await bcrypt.compare(input.password, user.password);

    if (!passwordIsValid) {
      throw new GraphQLError(e);
    }

    const token = signJwt(user);

    context.res.cookie('acessToken', token, {
      maxAge: 3.154e10, // 1day
      httpOnly: true,
      domain: 'localhost',
      path: '/',
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    });

    // Return the jwt
    return token;
  }

  async generateOTP(userId: string) {
    try {
      const user = await UserModel.findById(userId);

      if (!user) {
        throw new GraphQLError('User not found');
      }

      const base32_secret = generateRandomBase32();

      const totp = new OTPAuth.TOTP({
        issuer: 'robeavelii.com',
        label: 'Robel Fekadu',
        algorithm: 'SHA1',
        digits: 6,
        period: 15,
        secret: base32_secret,
      });

      const otpauth_url = totp.toString();

      await UserModel.findByIdAndUpdate(userId, {
        otp_auth_url: otpauth_url,
        otp_base32: base32_secret,
      });

      return {
        base32: base32_secret,
        otpauth_url,
      };
    } catch (error: any) {
      throw new GraphQLError(error.message);
    }
  }

  async verifyOTP(userId: string, token: string) {
    try {
      const user = await UserModel.findById(userId);
      if (!user) {
        throw new GraphQLError('User not found');
      }

      const totp = new OTPAuth.TOTP({
        issuer: 'robavelii.com',
        label: 'Robel Fekadu',
        algorithm: 'SHA1',
        digits: 6,
        period: 15,
        secret: user.otp_base32!,
      });

      const delta = totp.validate({ token });

      if (delta === null) {
        throw new GraphQLError('Invalid OTP');
      }

      const updatedUser = await UserModel.findByIdAndUpdate(
        userId,
        {
          otp_enabled: true,
          otp_verified: true,
        },
        { new: true }
      );

      return {
        otp_verified: true,
        user: {
          id: updatedUser?.id,
          name: updatedUser?.name,
          email: updatedUser?.email,
          otp_enabled: updatedUser?.otp_enabled,
        },
      };
    } catch (error: any) {
      throw new GraphQLError(error.message);
    }
  }

  async validateOTP(userId: string, token: string) {
    try {
      const user = await UserModel.findById(userId);
      if (!user) {
        throw new GraphQLError('User not found');
      }

      const totp = new OTPAuth.TOTP({
        issuer: 'robavelii.com',
        label: 'Robel Fekadu',
        algorithm: 'SHA1',
        digits: 6,
        period: 15,
        secret: user.otp_base32!,
      });

      const delta = totp.validate({ token, window: 1 });

      if (delta === null) {
        throw new GraphQLError('Invalid OTP');
      }

      return {
        otp_valid: true,
      };
    } catch (error: any) {
      throw new GraphQLError(error.message);
    }
  }

  async disableOTP(userId: string) {
    try {
      const user = await UserModel.findById(userId);
      if (!user) {
        throw new GraphQLError('User not found');
      }

      const updatedUser = await UserModel.findByIdAndUpdate(
        userId,
        {
          otp_enabled: false,
        },
        { new: true }
      );

      return {
        otp_disabled: true,
        user: {
          id: updatedUser?.id,
          name: updatedUser?.name,
          email: updatedUser?.email,
          otp_enabled: updatedUser?.otp_enabled,
        },
      };
    } catch (error: any) {
      throw new GraphQLError(error.message);
    }
  }
}

function generateRandomBase32() {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, '').substring(0, 24);
  return base32;
}

export default UserService;

