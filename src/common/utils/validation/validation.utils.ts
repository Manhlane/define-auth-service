import { validate, ValidationError } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { BadRequestException } from '@nestjs/common';
import { ValidationErrorUtils } from './validation-error.utils';

export class ValidationUtils {
  static async validate<T extends object>(
    dtoClass: new () => T,
    payload: Record<string, any>,
  ): Promise<T> {
    const instance = plainToInstance(dtoClass, payload);
    const errors: ValidationError[] = await validate(instance);

    if (errors.length > 0) {
      const formatted = ValidationErrorUtils.format(errors);
      throw new BadRequestException({
        message: 'Validation failed',
        errors: formatted,
      });
    }

    return instance;
  }
}
