/**
 * Core content types: modules -> lessons -> labs -> flags.
 * Progression is a DAG over lesson ids; a lesson unlocks when all its flags are solved.
 *
 * Plain-JSDoc typedefs (not TS interfaces): this file ships as .mjs and must
 * stay valid JavaScript so browsers can import it without transpilation.
 */

/**
 * @typedef {object} FlagDef
 * @property {string} id Stable id, e.g. "m1.eprocess.pid"
 * @property {string} sha256 hex of the exact accepted flag string (case-sensitive)
 * @property {string} prompt Shown before solving
 * @property {number} points Points awarded (CTF scoring)
 */

/**
 * @typedef {"ntsim"|"compiler"|"windbg"|"quiz"} LabKind
 */

/**
 * @typedef {object} LabDef
 * @property {string} id
 * @property {LabKind} kind
 * @property {string} title
 * @property {string} brief
 * @property {string} [scenario] Scenario/fixture id inside the track runtime
 * @property {"js"|"unicorn"} [backend] CPU backend for ntsim labs (default js)
 * @property {{path:string,content:string}[]} [starterFiles] Files preloaded into the student IDE
 * @property {FlagDef[]} flags
 */

/**
 * @typedef {object} LessonDef
 * @property {string} id
 * @property {string} title
 * @property {string} body MDX body file reference within the content package
 * @property {LabDef[]} labs
 * @property {string[]} requires
 */

/**
 * @typedef {"windows-user"|"windows-kernel"|"linux"|"hypervisor"|"uefi"|"misc"} TrackKind
 */

/**
 * @typedef {object} CourseModule
 * @property {string} id
 * @property {string} title
 * @property {TrackKind} track
 * @property {string} summary
 * @property {LessonDef[]} lessons
 */

/**
 * @typedef {object} CourseCatalog
 * @property {number} version
 * @property {CourseModule[]} modules
 */
