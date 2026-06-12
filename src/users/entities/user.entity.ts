import { Session } from 'src/session/entities/session.entity';
import { BaseEntity } from 'src/common/entities/base.entity/base.entity';
import { Entity, Column, OneToMany } from 'typeorm';

@Entity('users')
export class User extends BaseEntity {
  @Column({ unique: true })
  email: string;

  @Column()
  name: string;

  @Column({ nullable: true })
  businessName: string | null;

  @Column({ nullable: true })
  phone: string | null;

  @Column({ nullable: true })
  bankName: string | null;

  @Column({ nullable: true })
  accountNumber: string | null;

  @Column({ nullable: true })
  accountType: string | null;

  @Column({ type: 'text', nullable: true })
  avatarUrl: string | null;

  @Column()
  password: string;

  @Column({ default: false })
  isVerified: boolean;

  @Column('simple-array', { default: 'user' })
  roles: string[];

  @OneToMany(() => Session, (session) => session.user)
  sessions: Session[];
}
