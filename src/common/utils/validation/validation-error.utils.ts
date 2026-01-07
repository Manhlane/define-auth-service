import { ValidationError } from 'class-validator';

export class ValidationErrorUtils {
  static format(errors: ValidationError[]) {
    return errors.map((error) => ({
      property: error.property,
      constraints: error.constraints,
      children: error.children?.length
        ? this.format(error.children)
        : undefined,
    }));
  }
}
