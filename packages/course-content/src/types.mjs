/**
 * Core content types: modules -> lessons -> labs -> flags.
 * Progression is a DAG over lesson ids; a lesson unlocks when all its flags are solved.
 */

export interface FlagDef {
  /** Stable id, e.g. "m1.eprocess.pid" */
  id: string;
  /** sha256 hex of the exact accepted flag string (case-sensitive) */
  sha256: string;
  /** Shown before solving */
  prompt: string;
  /** Points awarded (CTF scoring) */
  points: number;
}

export type LabKind =
  | "ntsim"        // emulated Windows kernel scenario
  | "compiler"     // browser IDE compile task
  | "windbg"       // debugger interaction task
  | "quiz";        // pure question, answer is the flag

export interface LabDef {
  id: string;
  kind: LabKind;
  title: string;
  brief: string;
  /** Scenario/fixture id inside the track runtime, e.g. ntsim boot scenario */
  scenario?: string;
  /** Files preloaded into the student IDE for this lab */
  starterFiles?: { path: string; content: string }[];
  flags: FlagDef[];
}

export interface LessonDef {
  id: string;
  title: string;
  /** MDX body file reference within the content package */
  body: string;
  labs: LabDef[];
  requires: string[];
}

export interface CourseModule {
  id: string;
  title: string;
  track: "windows-user" | "windows-kernel" | "linux" | "hypervisor" | "uefi" | "misc";
  summary: string;
  lessons: LessonDef[];
}

export interface CourseCatalog {
  version: number;
  modules: CourseModule[];
}
