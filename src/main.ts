import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // ✅ CORS for your Next.js app on :3002 (and optional env origin)
  const allowedOrigins = [
    'http://localhost:3003',
    process.env.FRONTEND_ORIGIN ?? '',
  ].filter(Boolean);

  app.enableCors({    
    origin: allowedOrigins,                                // exact origins, not '*'
    methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,                                    // set true ONLY if you use cookies & fetch(..., { credentials: 'include' })
    maxAge: 86400,                                          // cache preflight
  });

  const config = new DocumentBuilder()
    .setTitle('define!. Auth API')
    .setDescription('Authentication endpoints for define!.')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(process.env.PORT);
  console.log(`Auth API running on ${await app.getUrl()}`);
}
bootstrap();
