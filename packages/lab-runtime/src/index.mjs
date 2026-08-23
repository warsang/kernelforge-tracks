/** Local-first persistence + CTF flag checking + lesson progression. */

// ---------------------------------------------------------------------------
// Hashing — works in Node (tests) and browser (WebCrypto fallback)
// ---------------------------------------------------------------------------

export async function sha256Hex(text, cryptoImpl = globalThis.crypto) {
  if (typeof cryptoImpl?.subtle?.digest === "function") {
    const buf = await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  // Node fallback for tests without global webcrypto
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Flag checking
// ---------------------------------------------------------------------------

/**
 * @param {string} submission raw user input
 * @param {object} flagDef { id, sha256 }
 */
export async function checkFlag(submission, flagDef) {
  const normalized = submission.trim();
  const digest = await sha256Hex(normalized);
  return timingSafeEqualStr(digest, flagDef.sha256.toLowerCase());
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Progression
// ---------------------------------------------------------------------------

const KEY_PROGRESS = "kf.progress.v1";

export function emptyProgress() {
  return {
    solvedFlags: {},      // flagId -> timestamp
    unlockedLessons: [],  // lesson ids currently unlocked
    completedLessons: [],
    points: 0,
  };
}

export function isLessonUnlocked(lesson, progress) {
  return lesson.requires.every((r) => progress.completedLessons.includes(r));
}

export function lessonFlagsSolved(lesson, progress) {
  const allFlags = lesson.labs.flatMap((l) => l.flags.map((f) => f.id));
  return allFlags.every((id) => progress.solvedFlags[id]);
}

/**
 * Pure reducer over progress state.
 * @returns {{progress: object, events: string[]}}
 */
export function submitFlagForProgress(progress, lesson, flagId, correct) {
  const events = [];
  const next = {
    ...progress,
    solvedFlags: { ...progress.solvedFlags },
    completedLessons: [...progress.completedLessons],
    unlockedLessons: [...progress.unlockedLessons],
  };

  if (!correct || next.solvedFlags[flagId]) {
    return { progress: next, events };
  }

  const flag = lesson.labs.flatMap((l) => l.flags).find((f) => f.id === flagId);
  next.solvedFlags[flagId] = Date.now();
  next.points += flag?.points ?? 0;
  events.push(`flag:${flagId}`);

  if (lessonFlagsSolved(lesson, next)) {
    if (!next.completedLessons.includes(lesson.id)) {
      next.completedLessons.push(lesson.id);
      events.push(`lesson-complete:${lesson.id}`);
      // unlock dependents
      // (caller re-evaluates with full catalog; recorded here as event only)
      events.push(`reevaluate-unlocks`);
    }
  }
  return { progress: next, events };
}

export * from "./backends.mjs";
