import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt'

import { UsersService } from 'src/users/services/users.service';
import { User } from 'src/users/entities/user.entity';
import { PayloadToken } from '../models/token.model';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService
    ) {}

    async validateUser(email: string, password: string) {
        const user = await this.usersService.findByEmail(email);
        if (user) {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const { password, ...response } = user.toJSON();
                return response;
            }
        }
        return null;
    }

    generateJWT(user: User) {
        const payload: PayloadToken = { role: user.role, sub: user._id };
        return {
            access_token: this.jwtService.sign(payload),
            user
        };
    }
}
