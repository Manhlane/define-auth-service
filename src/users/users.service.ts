import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrpyt from 'bcrypt';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private readonly userRepo: Repository<User>,
    ) { }

    async findByEmail(email: string): Promise<User | null> {
        return this.userRepo.findOne({ where: { email } });
    }

    async findById(id: string): Promise<User | null> {
        return this.userRepo.findOne({ where: { id } });
    }

    async createUser(userData: Partial<User>): Promise<User> {
        const user = this.userRepo.create(userData);
        return this.userRepo.save(user);
    }

    async updateUser(userId: string, updateData: Partial<User>): Promise<void> {
        await this.userRepo.update(userId, updateData);
    }

    async create(data: { email: string; name: string; password: string }): Promise<User> {
        const existing = await this.userRepo.findOne({ where: { email: data.email } });
        if (existing) throw new ConflictException('Email already in use');
      
        const user = this.userRepo.create({
          email: data.email,
          name: data.name,
          password: data.password, 
          isVerified: false,
          roles: ['user'],
        });
      
        return this.userRepo.save(user);
      }
      
}
