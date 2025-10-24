-- AlterTable
ALTER TABLE "User" ADD COLUMN     "totTempSecret" TEXT,
ADD COLUMN     "totpEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "totpSecret" TEXT;
