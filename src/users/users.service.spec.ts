import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { ConflictException } from '@nestjs/common';

describe('UsersService', () => {
  let service: UsersService;
  let repository: jest.Mocked<{
    findOne: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    update: jest.Mock;
  }>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    repository = module.get(getRepositoryToken(User));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('findByEmail should normalize email before querying', async () => {
    repository.findOne.mockResolvedValue(null);

    await service.findByEmail('USER@Example.COM');

    expect(repository.findOne).toHaveBeenCalledWith({ where: { email: 'user@example.com' } });
  });

  it('createUser should lower-case email before persisting', async () => {
    const payload = { email: 'Camel@Example.com', name: 'Camel', password: 'hash' } as Partial<User>;
    const entity = { id: 'id', ...payload, email: 'camel@example.com' } as User;
    repository.create.mockReturnValue(entity);
    repository.save.mockResolvedValue(entity);

    await service.createUser(payload);

    expect(repository.create).toHaveBeenCalledWith({
      ...payload,
      email: 'camel@example.com',
    });
    expect(repository.save).toHaveBeenCalledWith(entity);
  });

  it('create should throw ConflictException when email already exists', async () => {
    repository.findOne.mockResolvedValue({ id: 'existing' } as User);

    await expect(
      service.create({ email: 'taken@example.com', name: 'Taken', password: 'hash' }),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('create should normalize email and assign defaults', async () => {
    repository.findOne.mockResolvedValue(null);
    const saved = {
      id: 'new-id',
      email: 'new@example.com',
      name: 'New',
      password: 'hash',
      isVerified: false,
      roles: ['user'],
    } as User;
    repository.create.mockReturnValue(saved);
    repository.save.mockResolvedValue(saved);

    const result = await service.create({
      email: 'New@Example.com',
      name: 'New',
      password: 'hash',
    });

    expect(repository.create).toHaveBeenCalledWith({
      email: 'new@example.com',
      name: 'New',
      password: 'hash',
      isVerified: false,
      roles: ['user'],
    });
    expect(result).toBe(saved);
  });
});
