import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {

    constructor(
        @InjectRepository(User)
        private readonly userRepo: Repository<User>,
      ) {}
    
      async findByEmail(email: string): Promise<User | undefined> {
        return this.userRepo.findOne({ where: { email } });
      }
}
