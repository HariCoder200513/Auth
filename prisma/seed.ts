import 'dotenv/config';
import { PrismaClient, Role } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const username = process.env.SEED_ADMIN_USERNAME?.trim();

  if (!username) {
    throw new Error('SEED_ADMIN_USERNAME is required');
  }

  await prisma.user.upsert({
    where: { username },
    update: { role: Role.admin, disabled: false },
    create: { username, role: Role.admin }
  });

  console.log(`Seeded admin user "${username}". Register a passkey for this username in the app.`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
