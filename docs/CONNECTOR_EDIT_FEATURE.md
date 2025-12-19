# Connector Edit Feature Implementation

## Overview
This document describes the implementation of the connector edit functionality in the web UI, allowing users to edit connectors using the same web form interface as the create functionality.

## Changes Made

### 1. Added Edit Form UI
- Created a new edit form section (`editConnectorForm`) in the connector management page
- The edit form mirrors the create form with all the same fields:
  - Connector name
  - Inbound API selection with search/autocomplete
  - Outbound API selection with search/autocomplete
  - Transformation method selection (Python Script or Field Mappings)
  - Python script textarea (when script method is selected)
  - Field mapping drag-and-drop interface (when mappings method is selected)
  - Active/inactive checkbox

### 2. Enhanced JavaScript Functions

#### Edit Form Management
- `editConnector(id, name, inboundAPIId, outboundAPIId, isActive)` - Opens the edit form and populates it with existing connector data
- `loadConnectorForEdit(connectorId)` - Fetches full connector details including field mappings and Python script
- `cancelEditConnectorForm()` - Closes the edit form and resets all fields

#### Field Mapping for Edit Form
- `editFieldMappings` - Separate array to store field mappings for the edit form
- `toggleEditTransformationMethod()` - Switches between script and mappings mode in edit form
- `loadEditAPIFields()` - Loads API schema fields for the edit form
- `addEditFieldMapping()` - Adds manual field mapping in edit form
- `renderEditFieldMappings()` - Renders the field mappings list in edit form
- `removeEditFieldMapping(index)` - Removes a field mapping from edit form
- `getEditFieldMappings()` - Returns the current field mappings array
- `editDrop(event)` - Handles drag-and-drop for field mappings in edit form

#### Form Validation and Submission
- `validateEditConnectorForm()` - Validates all edit form fields before submission
- `showEditFieldError(fieldId, message)` - Displays validation errors
- `clearEditFormErrors()` - Clears all validation error messages
- `updateConnector(id, name, inboundAPIId, outboundAPIId, script, isActive)` - Submits the updated connector data

#### Enhanced API Selection
- Updated `selectAPI(type, api)` to detect edit mode and load fields accordingly
- Updated `filterAPIs(type)` to work with both create and edit form dropdowns

### 3. Backend Changes

#### New Route
- Added GET route for individual connectors: `/manage/org/{orgID}/connectors/{connectorID}`

#### New Handler
- `HandleGetConnector(w http.ResponseWriter, r *http.Request)` - Returns full connector details including field mappings for the edit form

#### Updated Handler
- `HandleUpdateConnector(w http.ResponseWriter, r *http.Request)` - Updated to use `decodeJSONRequest` helper for consistency with security middleware

## User Workflow

### Editing a Connector
1. User clicks the "Edit" button on a connector in the table
2. The edit form appears below the page header with all fields pre-populated
3. User can modify any field:
   - Change connector name
   - Select different inbound/outbound APIs
   - Switch between Python script and field mappings
   - Modify existing field mappings or add new ones
   - Toggle active/inactive status
4. User clicks "Update Connector" to save changes
5. Form validates all fields before submission
6. Success message appears and page reloads to show updated connector

### Field Mapping in Edit Mode
- When a connector with existing field mappings is loaded, the edit form automatically:
  - Selects the "Field Mappings" transformation method
  - Loads the API schemas for both inbound and outbound APIs
  - Displays all existing field mappings
  - Allows adding, removing, or modifying mappings

### Python Script in Edit Mode
- When a connector with a Python script is loaded, the edit form automatically:
  - Selects the "Python Script" transformation method
  - Populates the textarea with the existing script
  - Allows editing the script

## Technical Details

### Form Isolation
- Create and edit forms are completely separate to avoid state conflicts
- Each form has its own:
  - Field mapping array (`fieldMappings` vs `editFieldMappings`)
  - API field containers (`inboundFields` vs `editInboundFields`)
  - Validation functions
  - Submission handlers

### Data Loading
- Edit form fetches full connector details via GET request to load:
  - Field mappings array
  - Python script content
  - Current transformation method
- API schemas are loaded dynamically when switching to mappings mode

### Validation
- Same validation rules as create form:
  - Connector name required (min 3 characters)
  - Inbound and outbound APIs required
  - Python script required if using script method (min 10 characters)
  - At least one field mapping required if using mappings method

### Update Behavior
- When switching from script to mappings: script is cleared, mappings are preserved
- When switching from mappings to script: mappings are cleared, script is preserved
- Update endpoint receives the complete connector object with all fields

## Files Modified
- `internal/handlers/auth_ui.go` - Added edit form UI, JavaScript functions, and backend handlers

## Testing Recommendations
1. Test editing a connector with Python script
2. Test editing a connector with field mappings
3. Test switching between script and mappings in edit mode
4. Test validation errors in edit form
5. Test canceling edit operation
6. Test updating connector with different API selections
7. Test drag-and-drop field mapping in edit mode
8. Test that create and edit forms don't interfere with each other

## Future Enhancements
- Add inline editing in the table
- Add bulk edit functionality
- Add version history for connectors
- Add preview/test functionality before saving changes
- Add confirmation dialog when switching transformation methods with unsaved changes
