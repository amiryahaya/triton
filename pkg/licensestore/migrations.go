
	// Version 3: Migrate ID columns from TEXT to native UUID (UUIDv7)
	// Drop FK constraints first, alter all columns, then re-add FKs.
	// Use COALESCE to handle empty strings in org_id (convert to NULL before casting to UUID).
	TRUNCATE TABLE organizations CASCADE;

	ALTER TABLE activations DROP CONSTRAINT IF EXISTS activations_license_id_fkey;
	ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_org_id_fkey;

	ALTER TABLE organizations ALTER COLUMN id TYPE UUID USING id::uuid;

	ALTER TABLE licenses ALTER COLUMN id TYPE UUID USING id::uuid;
	ALTER TABLE licenses ALTER COLUMN org_id TYPE UUID USING NULLIF(org_id, '')::uuid;

	ALTER TABLE activations ALTER COLUMN id TYPE UUID USING id::uuid;
	ALTER TABLE activations ALTER COLUMN license_id TYPE UUID USING license_id::uuid;

	ALTER TABLE audit_log ALTER COLUMN license_id TYPE UUID USING license_id::uuid;
	ALTER TABLE audit_log ALTER COLUMN org_id TYPE UUID USING NULLIF(org_id, '')::uuid;

	ALTER TABLE licenses ADD CONSTRAINT licenses_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
	ALTER TABLE activations ADD CONSTRAINT activations_license_id_fkey FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE RESTRICT;
