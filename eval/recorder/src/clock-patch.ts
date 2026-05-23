/**
 * In-page clock patch — injected via Playwright's `addInitScript()`
 * before any user JS runs.
 *
 * What we patch (exactly four things, NEVER more):
 *   - requestAnimationFrame   — callbacks queued, fire on __advance
 *   - cancelAnimationFrame    — removes a queued callback
 *   - performance.now()       — returns the virtual elapsed ms
 *   - Date.now() (+ new Date()) — returns epoch + virtual ms
 *
 * What we DO NOT touch:
 *   - setTimeout / setInterval / setImmediate / queueMicrotask
 *     React's scheduler reads these for its own work loop; patching
 *     them desyncs the renderer and the recording goes off-rails.
 *     Lesson burned in during NEBULA — see
 *     `[[feedback_deterministic_browser_recording]]`.
 *
 * Driver protocol (from the Node side):
 *   - call `window.__toolwall_advance(ms)` per frame; it bumps the
 *     virtual clock and drains the rAF queue once.
 *   - call `window.__toolwall_clock()` to read the current virtual
 *     elapsed ms (handy for sanity assertions).
 *
 * The script is intentionally tiny and self-contained so it can be
 * stringified and shipped via `addInitScript()`.
 */
export const CLOCK_PATCH_SOURCE = String.raw`
(() => {
  if (window.__toolwall_clock_installed) return;
  window.__toolwall_clock_installed = true;

  var virtualMs = 0;
  var realDateNow = Date.now.bind(Date);
  var epochAtStart = realDateNow();

  var rafCallbacks = [];
  var rafNextId = 1;

  // ---- patched rAF / cAF ---------------------------------------
  window.requestAnimationFrame = function patchedRAF(cb) {
    var id = rafNextId++;
    rafCallbacks.push({ id: id, fn: cb });
    return id;
  };
  window.cancelAnimationFrame = function patchedCAF(id) {
    for (var i = 0; i < rafCallbacks.length; i++) {
      if (rafCallbacks[i].id === id) {
        rafCallbacks.splice(i, 1);
        return;
      }
    }
  };

  // ---- patched performance.now ---------------------------------
  Object.defineProperty(performance, "now", {
    configurable: true,
    writable: true,
    value: function patchedNow() { return virtualMs; },
  });

  // ---- patched Date.now + new Date() ---------------------------
  Date.now = function patchedDateNow() { return epochAtStart + virtualMs; };
  var RealDate = Date;
  function FakeDate() {
    if (!(this instanceof FakeDate)) {
      return new RealDate(epochAtStart + virtualMs).toString();
    }
    if (arguments.length === 0) {
      return new RealDate(epochAtStart + virtualMs);
    }
    return new (Function.prototype.bind.apply(
      RealDate,
      [null].concat(Array.prototype.slice.call(arguments))
    ))();
  }
  FakeDate.prototype = RealDate.prototype;
  FakeDate.UTC = RealDate.UTC;
  FakeDate.parse = RealDate.parse;
  FakeDate.now = Date.now;
  window.Date = FakeDate;

  // ---- driver protocol ------------------------------------------
  window.__toolwall_advance = function (deltaMs) {
    virtualMs += deltaMs;
    // Snapshot the queue before draining so callbacks scheduled
    // *during* drain land in the NEXT frame, not this one. This
    // matches the browser's real rAF semantics.
    var queue = rafCallbacks;
    rafCallbacks = [];
    for (var i = 0; i < queue.length; i++) {
      try { queue[i].fn(virtualMs); }
      catch (e) { console.error("[toolwall-recorder] rAF callback threw", e); }
    }
  };

  window.__toolwall_clock = function () { return virtualMs; };
  window.__toolwall_raf_depth = function () { return rafCallbacks.length; };
})();
`;
