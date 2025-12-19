# Default Admin User

The API Translation Platform automatically creates a default admin user during database initialization.

## Default Credentials

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@system.local`
- **Role**: `global_admin`

## First Login

1. Start the application:
   ```bash
   make dev1
   ```

2. Open your browser and navigate to: `http://localhost:8080`

3. Click on "Login" and use the default credentials above

4. **IMPORTANT**: Change the default password immediately after first login for security reasons

## Changing the Default Password

### Via Web Interface
1. Log in with the default credentials
2. Navigate to "User Management" or "Profile Settings"
3. Change your password to a secure one

### Via Database (if needed)
```sql
-- Connect to your database and run:
UPDATE users 
SET password_hash = crypt('your_new_password', gen_salt('bf')), 
    updated_at = NOW() 
WHERE username = 'admin';
```

## Admin User Capabilities

The default admin user has `global_admin` role and can:

- Manage all organisations
- Create, update, and delete users
- Configure API endpoints and connectors
- View system-wide metrics and logs
- Access all administrative functions

## Security Notes

1. **Change the default password immediately** after first login
2. Consider creating additional admin users and disabling the default one in production
3. Use strong passwords and enable two-factor authentication if available
4. Regularly audit admin user access and permissions

## Recreating the Admin User

If you need to recreate the admin user, you can:

1. Run the database initialization script again:
   ```bash
   DB_PASSWORD=your_db_password ADMIN_PASSWORD=your_admin_password ./scripts/init-database.sh
   ```

2. Or manually execute the SQL:
   ```sql
   INSERT INTO users (id, organisation_id, username, email, password_hash, role, is_active, created_at, updated_at)
   VALUES (
       gen_random_uuid(),
       (SELECT id FROM organisations WHERE name = 'System Administration' LIMIT 1),
       'admin',
       'admin@system.local',
       crypt('admin123', gen_salt('bf')),
       'global_admin',
       true,
       NOW(),
       NOW()
   ) ON CONFLICT (username) DO UPDATE SET
       password_hash = crypt('admin123', gen_salt('bf')),
       updated_at = NOW();
   ```

## Troubleshooting

### Cannot Login
- Verify the database is running and accessible
- Check that the users table exists and contains the admin user
- Ensure the application is connecting to the correct database

### Password Not Working
- The admin user password is reset to `admin123` every time the init script runs
- Check for any password policy restrictions
- Verify the password hashing is working correctly

### Missing Permissions
- Ensure the admin user has `global_admin` role
- Check that the user is marked as active (`is_active = true`)
- Verify the user is associated with the correct organisation