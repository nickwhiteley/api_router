# API Schema Management Guide

## How to Define API Schemas

### Location
API schemas can be managed from the **API Management** page in your organization dashboard.

### Step-by-Step Instructions

#### 1. Navigate to API Management
- Log in to your organization dashboard
- Click on **"API Management"** or navigate to `/manage/org/{your-org-id}/apis`

#### 2. Find Your API
- Locate the API you want to define a schema for in the API list
- Each API has several action buttons: **Schema**, Edit, Test, Delete

#### 3. Click the "Schema" Button
- Click the **"Schema"** button for the API you want to configure
- A modal dialog will open showing the current schema status

### Schema Upload Options

The schema management modal provides three ways to define your API schema:

#### Option 1: Upload Sample JSON Data (Recommended)
This is the easiest method - the system automatically infers the schema from your sample data.

**Steps:**
1. Select **"Upload Sample JSON Data"** (selected by default)
2. Either:
   - **Drag and drop** a JSON file into the upload area, OR
   - Click **"Choose File"** to browse for a JSON file, OR
   - **Paste** JSON data directly into the text area
3. Click **"Save Schema"**

**Example Sample Data:**
```json
{
  "user": {
    "name": "John Doe",
    "email": "john@example.com",
    "profile": {
      "age": 30,
      "city": "New York"
    }
  },
  "active": true
}
```

The system will automatically detect:
- Field paths: `user`, `user.name`, `user.email`, `user.profile`, `user.profile.age`, `user.profile.city`, `active`
- Field types: `object`, `string`, `string`, `object`, `integer`, `string`, `boolean`

#### Option 2: Upload JSON Schema
For more precise control, you can upload a standard JSON Schema definition.

**Steps:**
1. Select **"Upload JSON Schema"**
2. Paste your JSON Schema definition
3. Click **"Save Schema"**

**Example JSON Schema:**
```json
{
  "type": "object",
  "required": ["name", "email"],
  "properties": {
    "name": {
      "type": "string",
      "description": "User's full name"
    },
    "email": {
      "type": "string",
      "format": "email",
      "description": "User's email address"
    },
    "age": {
      "type": "integer",
      "minimum": 0
    }
  }
}
```

#### Option 3: Define Fields Manually
For custom field definitions (future feature - currently uses same interface as sample data).

### Viewing Existing Schemas

When you open the schema management modal for an API that already has a schema:
- You'll see a **green checkmark** (✅) indicating the schema exists
- The number of defined fields is displayed
- A scrollable list shows all current fields with their types
- You can update the schema by uploading new data
- You can delete the schema using the **"Delete Schema"** button

### Using Schemas in Field Mapping

Once you've defined schemas for your APIs:

1. **Navigate to Connector Management**
   - Go to `/manage/org/{your-org-id}/connectors`
   - Click **"Create Connector"**

2. **Select Transformation Method**
   - Choose **"Field Mappings (Drag & Drop)"**

3. **Select APIs**
   - Choose your inbound API
   - Choose your outbound API
   - The system will automatically load the schemas

4. **View Real Fields**
   - The left panel shows inbound API fields
   - The right panel shows outbound API fields
   - Each field displays its type (string, integer, object, etc.)

5. **Create Mappings**
   - Drag fields from inbound to outbound
   - Or click **"Add Manual Mapping"** to type field paths
   - Add optional Python transformation scripts per field

### Best Practices

#### For Inbound APIs
- Use actual request examples from your clients
- Include all possible fields, even optional ones
- Use realistic data types and values

#### For Outbound APIs
- Use actual response examples from the target API
- Document required vs optional fields
- Include nested objects and arrays

#### Schema Maintenance
- Update schemas when API structures change
- Test field mappings after schema updates
- Keep sample data representative of real usage

### Troubleshooting

#### "No schema defined" Message
- The API doesn't have a schema yet
- Click the upload area to add one
- Use sample data from actual API requests/responses

#### "Error loading schema"
- Check that the API exists
- Verify you have permission to access the API
- Try refreshing the page

#### "Invalid JSON" Error
- Ensure your JSON is properly formatted
- Use a JSON validator to check syntax
- Remove any comments (JSON doesn't support comments)

#### Fields Not Showing in Connector Creation
- Verify the schema was saved successfully
- Check that you selected the correct APIs
- Refresh the connector creation page

### Advanced Features

#### Drag and Drop Files
- Simply drag a `.json` file from your file explorer
- Drop it onto the upload area
- The file contents will be automatically loaded

#### Copy/Paste from API Documentation
- Copy example requests/responses from API docs
- Paste directly into the text area
- The system handles formatting automatically

#### Schema Versioning (Future)
- Track changes to schemas over time
- Compare different schema versions
- Rollback to previous schemas

### API Endpoints

For programmatic access, schemas can be managed via REST API:

```bash
# Get schema
GET /manage/org/{orgID}/apis/{apiID}/schema

# Create/Update schema
POST /manage/org/{orgID}/apis/{apiID}/schema
Content-Type: application/json
{
  "schema_type": "custom",
  "schema_content": {
    "sample_data": { ... }
  }
}

# Delete schema
DELETE /manage/org/{orgID}/apis/{apiID}/schema
```

## Summary

Schema management is now easily accessible from the API Management page:
1. Click **"Schema"** button next to any API
2. Drag and drop a JSON file or paste JSON data
3. Click **"Save Schema"**
4. Use the defined fields in connector field mappings

This eliminates the need for mock data and ensures your field mappings work with real API structures!