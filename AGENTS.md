# AI Coding Assistant Instructions

Write code that breathes. Think Ruby-like elegance meets modern js.

Important boundaries:

- You do not touch files specified in `.gitignore`

==============================

## 1. Code Philosophy

**Code is written for human eyes**: Code is a description of the intent of a programmer, it must communicate the intent. For machines, the syntax and style is not relevant. Therefore, code style must be optimised for human eyes and mental models.

**More comments is better than less comments**: Reading code can clarify function but not intention. Comments are a reminder to self, or an explanation to coworkers.

**Readability Through Spacing**: Code needs room to breathe. Spacing makes structure visible at a glance.

**Remember**: Code is read far more than it's written. Make it beautiful, make it breathe, make it obvious.

==============================

## 2. Syntax preferences

Code should be elegant, not use superfluous characters, and have space to breathe. For example: do not use semicolons, add space in brackets. The linter will show you syntax preferences, to that end with every change learn the styling by:

1. save your changes and look at the syntax
2. run `npm run lint` and ignore the command output
3. look at how the linter changed the style, and mimic it in future responses.

==============================

## 3. Tooling preferences

### LLM agent context

Any LLM including you should always:

- Read the `AGENTS.md` file for instructions
- Check if `SPECIFICATION.md` exists, if so read it
- Check if `SPECIFICATION.*.md` patterned files exist, if so read them for context
- Check for all `*.md` files in the project root

### Node.js usage

- Use `nvm` for version management, with the latest LTS (24) in the `.nvmrc`
- Do not modify files in `node_modules/`
- Environment variables are stored in `.env` which is supported by node without dependencies
- Frontend code should use Vite for bundling
- Backend code should use Node.js
- Prefer javascript over typescript, including when setting up vite projects

### React usage

- Frontends should be built in react
- React should be used in frontend mode (no server components)
- Routing is done with `react-router` BrowserRouter
- State is put in the URL where possible using the `use-query-params` npm package
- State that is used in multiple places at once uses `zustand`
- Components follow a structure inspired by Atomic Design where they are split into:
  - Atoms: stateless components
  - Molecules: stateful components (may use Atoms)
  - Pages: components rendered by the router

File structure in a react project:

```bash
.
├── assets
├── package-lock.json
├── package.json
├── public
│   ├── assets
│   ├── favicon.ico
│   ├── logo192.png
│   ├── logo512.png
│   └── robots.txt
├── src
│   ├── App.jsx
│   ├── components
│   │   ├── atoms
│   │   ├── molecules
│   │   └── pages
│   ├── hooks
│   ├── index.css
│   ├── index.jsx
│   ├── modules
│   ├── routes
│   │   └── Routes.jsx
│   └── stores
└── vite.config.js
```

### Using Mentie Helpers

If `mentie` is installed, **always use its utilities**. Check `node_modules/mentie/index.js` for available exports.

```js
import { log, multiline_trim, shuffle_array } from 'mentie'

log.info( `User logged in:`, user_id )

const query = multiline_trim( `
    SELECT * FROM users
    WHERE active = true
` )

const randomized = shuffle_array( items )
```

==============================

## 3. Code style preferences

### Always use template literals instead of strings
```js
// Use literals for regular strings
const name = `Ada Localace`

// Use templates for string manipulation too
const annotated_name = `${ name } ${ Math.random() }`
```


### snake_case for Everything
```js
const timeout_ms = 5_000
const user_name = 'John'
const fetch_user_data = async ( user_id ) => { }
```

### Use comments to describe intent
```js
import { abort_controller } from 'mentie'

// Load the users with a timeout to prevent hanging
const fetch_options = abort_controller( { timeout_ms: 10_000 } )
const { uids } = await fetch( 'https://...', fetch_options ).then( res => res.json() )

// Parallel fetch resulting data to optimise speed
const downstream_data = await Promise.all( uids.map( async uid => fetch( `https://...?uid=${ uid }` ) ) )
```


### Prioritise semantic clarity over optimisation
Don't reassign variables. Create new bindings for each transformation step.
```js
// Parse a dataset - each step is clear and traceable
const data = []
const filtered_data = data.filter( ( { relevant_number } ) => relevant_number > 1.5 )
const restructured_data = filtered_data.map( ( { base_value, second_value } ) => ( { composite_value: base_value * second_value } ) )
return restructured_data
```


### Lean towards onelining single statements
Single statements can be on one line. Multiple statements need blocks.
```js
// ✅ Single statement - oneline it
if( condition ) log.info( `Message` )
const filtered_data = data.filter( ( { relevant_property } ) => relevant_property )
```


### Functional Programming Over Loops

Prefer `.map()`, `.filter()`, `.reduce()`, `.find()`, `.some()`, `.every()` over `for`/`while` loops.

```js
const active_users = users.filter( u => u.active )
const user_names = active_users.map( u => u.name )
const total_age = user_names.reduce( ( sum, age ) => sum + age, 0 )
```


### JSDoc for Exported Functions

**CRITICAL**: Every exported function MUST have JSDoc. Verify before finishing!

```js
/**
 * Fetches user data from the API
 * @param {string} user_id - The ID of the user to fetch
 * @returns {Promise<Object>} User data object
 */
export const fetch_user = async ( user_id ) => {
    const response = await api.get( `/users/${ user_id }` )
    return response.data
}
```

### Error Handling

Only at boundaries (user input, external APIs). Trust internal code. Remember `finally` for cleanup!

```js
const fetch_user = async ( id ) => {

    try {
        start_loading()
        const response = await api.get( `/users/${ id }` )
        return response.data
    } catch( error ) {
        throw new Error( `Failed to fetch user: ${ error.message }` )
    } finally {
        stop_loading()
    }
}
```

### Complete example of well styled code

```js
/**
 * Fetches and processes active users from the API
 * @param {Object} options
 * @param {Array} options.user_ids - User ids to fetch
 * @param {Number} options.limit - Limit the amount of users to fetch
 * @returns {Promise<Array>} Processed user objects
 */
export async function fetch_and_process_users( { user_ids, limit=5 } = {} )  {

    // Get users to ensure up to date data
    const users = await api.get( `/users`, { user_ids, limit } )

    // Keep only active users to prevent wasting time on inactive ones
    const filtered_users = users.filter( ( { active } ) => active )

    // Annotate users with value based on local conversion so we can show the user the computed values
    const annotated_users = filtered_users.map( ( { score, user } ) => ( { score: score * local_conversion_value, ...user } ) )

    // Return users with annotated data
    return annotated_users
}

```


### React Specific styling

**Exception to snake_case**: React component names MUST be PascalCase (required by React/JSX).

```js
// ✅ Components are PascalCase
const UserProfile = ( { user_id } ) => { }
const DataTable = () => { }

// ✅ Everything else is snake_case
const user_name = `John`
const fetch_user_data = async ( user_id ) => { }
```

**File naming**: Component files use PascalCase to match component name.
- `UserProfile.jsx` - Component files
- `fetch_user_data.js` - Utility files

**Event handlers**:
- Do not name things after the event (e.g. `on_click`) but name them actions (e.g. `save_user`)

**JSX spacing and structure**:
```js
// Styled and stateless sections use arrow functions or variables
const Header = styled.aside`
    color: red;
`

// Use JSX comments to separate sections
export function UserProfile( { user_id, on_update } ) {

    // Hooks at the top
    const [ user_data, set_user_data ] = useState( null )
    const [ is_loading, set_is_loading ] = useState( false )

    // Effects after hooks
    useEffect( () => {
        fetch_user_data( user_id ).then( set_user_data )
    }, [ user_id ] )

    // Event handlers
    const update_user = () => on_update( user_data )

    // Conditional rendering
    if( is_loading ) return <LoadingSpinner />

    // Do not add () around returned jsx.
    return <>

            { /* Profile header section */ }
            <Header title={ user_data.name } />

            { /* Profile details */ }
            <div className="profile">
                { user_data.details }
            </div>

            { /* Actions */ }
            <Button on_click={ update_user }>Save</Button>

        </>
}

// Lists need keys
const user_list = users.map( ( user ) => <UserCard key={ user.id } user={ user } /> )

// Props always have spacing
<Component prop={ value } />
<div className="foo">{ children }</div>
```





