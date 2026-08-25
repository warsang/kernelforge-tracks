/**
 * Core content shapes (JSDoc — runtime is plain ESM):
 *
 * @typedef  {Object} FlagDef
 * @property {string} id            stable id, e.g. "m1.eprocess.pid"
 * @property {string} sha256        sha256 hex of the exact accepted flag string
 * @property {string} prompt        shown before solving
 * @property {number} points        CTF scoring
 *
 * @typedef {"ntsim"|"compiler"|"windbg"|"quiz"|"sogen"|"linux"} LabKind
 *
 * @typedef {Object} LabDef
 * @property {string} id
 * @property {LabKind} kind
 * @property {string} title
 * @property {string} brief
 * @property {string} [scenario]    scenario/fixture id in the track runtime
 * @property {{path: string, content: string}[]} [starterFiles]
 * @property {FlagDef[]} flags
 *
 * @typedef {Object} LessonDef
 * @property {string} id
 * @property {string} title
 * @property {string} body          MDX body reference within the content package
 * @property {LabDef[]} labs
 * @property {string[]} requires    lesson ids that must complete first
 *
 * @typedef {Object} CourseModule
 * @property {string} id
 * @property {string} title
 * @property {"windows-user"|"windows-kernel"|"windows-userland"|"linux-kernel"|"reversing"
 *           |"linux"|"hypervisor"|"uefi"|"misc"} track
 * @property {string} summary
 * @property {LessonDef[]} lessons
 *
 * @typedef {Object} CourseCatalog
 * @property {number} version
 * @property {CourseModule[]} modules
 */
