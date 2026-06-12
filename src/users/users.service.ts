import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email: email.toLowerCase() } });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { id } });
  }

  async createUser(userData: Partial<User>): Promise<User> {
    const data = { ...userData };
    if (data.email) {
      data.email = data.email.toLowerCase();
    }
    const user = this.userRepo.create(data);
    return this.userRepo.save(user);
  }

  async updateUser(userId: string, updateData: Partial<User>): Promise<void> {
    await this.userRepo.update(userId, updateData);
  }

  async create(data: {
    email: string;
    name: string;
    password: string;
    businessName?: string | null;
    phone?: string | null;
    bankName?: string | null;
    accountNumber?: string | null;
    accountType?: string | null;
    avatarUrl?: string | null;
    isVerified?: boolean;
    roles?: string[];
  }): Promise<User> {
    const normalizedEmail = data.email.toLowerCase();
    const existing = await this.userRepo.findOne({
      where: { email: normalizedEmail },
    });
    if (existing) throw new ConflictException('Email already in use');

    const user = this.userRepo.create({
      email: normalizedEmail,
      name: data.name,
      businessName: data.businessName ?? null,
      phone: data.phone ?? null,
      bankName: data.bankName ?? null,
      accountNumber: data.accountNumber ?? null,
      accountType: data.accountType ?? null,
      avatarUrl: data.avatarUrl ?? null,
      password: data.password,
      isVerified: data.isVerified ?? false,
      roles: data.roles ?? ['user'],
    });

    return this.userRepo.save(user);
  }
}
